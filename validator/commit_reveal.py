"""
Commit-Reveal Flow — Python integration with CommitReveal.sol.

Implements the two-phase anti-theft mechanism:
  Phase 1 (Commit):  Miner hashes their exploit + a random nonce, submits hash on-chain
  Phase 2 (Reveal):  After commit window, miner reveals the exploit + nonce for validation

Timeline:
  [Task opens] ──2 hours──▶ [Commit closes] ──4 hours──▶ [Reveal closes]

On-chain contract: CommitReveal.sol
  - openTask(bytes32 taskId)
  - commit(bytes32 taskId, bytes32 commitHash)
  - reveal(bytes32 taskId, bytes32 exploitArtifactHash, bytes32 nonce)
  - getEarliestReveal(bytes32 taskId, bytes32 exploitArtifactHash)
  - isCommitWindowOpen(bytes32 taskId) → bool
  - isRevealWindowOpen(bytes32 taskId) → bool
"""

import hashlib
import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Ensure Foundry tools available
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
if FOUNDRY_BIN.exists():
    os.environ["PATH"] = str(FOUNDRY_BIN) + ":" + os.environ.get("PATH", "")


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class CommitRecord:
    """Local record of a commit (persisted so the miner can reveal later)."""
    task_id: str                     # bytes32 hex
    exploit_artifact_hash: str       # keccak256 of exploit source, bytes32 hex
    nonce: str                       # random bytes32 hex
    commit_hash: str                 # keccak256(taskId || artifactHash || nonce)
    committed_at: float = 0.0       # Unix timestamp
    tx_hash: str = ""               # On-chain tx hash
    revealed: bool = False
    reveal_tx_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CommitRecord":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class RevealResult:
    """Result of a reveal operation."""
    success: bool
    task_id: str
    exploit_artifact_hash: str
    tx_hash: str = ""
    error: str = ""
    earliest_committer: str = ""    # Address of earliest commitment for this artifact


# ── Commit-Reveal Client ────────────────────────────────────────────────────

class CommitRevealClient:
    """
    Client for interacting with the CommitReveal.sol contract.

    Supports both live on-chain mode (cast send/call) and local simulation mode.
    """

    def __init__(
        self,
        contract_address: str,
        rpc_url: str = "http://127.0.0.1:8545",
        private_key: str = "",
        miner_address: str = "",
        data_dir: Optional[Path] = None,
    ):
        self.contract_address = contract_address
        self.rpc_url = rpc_url
        self.private_key = private_key
        self.miner_address = miner_address
        self.data_dir = data_dir or Path("data/commit-reveal")
        self.data_dir.mkdir(parents=True, exist_ok=True)

    # ── Commit Phase ─────────────────────────────────────────────────────

    def prepare_commit(
        self,
        task_id: str,
        exploit_source: str,
    ) -> CommitRecord:
        """
        Prepare a commitment for an exploit submission.

        Generates a random nonce and computes the commit hash:
        H = keccak256(abi.encodePacked(taskId, exploitArtifactHash, nonce))

        Returns a CommitRecord with the nonce (MUST be saved locally for reveal).
        """
        # Compute exploit artifact hash: keccak256 of source code
        artifact_hash = self._keccak256_hex(exploit_source.encode())

        # Generate secure random nonce
        nonce = "0x" + secrets.token_hex(32)

        # Compute commit hash: keccak256(abi.encodePacked(taskId, artifactHash, nonce))
        commit_hash = self._compute_commit_hash(task_id, artifact_hash, nonce)

        record = CommitRecord(
            task_id=task_id,
            exploit_artifact_hash=artifact_hash,
            nonce=nonce,
            commit_hash=commit_hash,
            committed_at=time.time(),
        )

        return record

    def submit_commit(self, record: CommitRecord) -> CommitRecord:
        """
        Submit a commit hash on-chain via cast send.

        Calls: CommitReveal.commit(bytes32 taskId, bytes32 commitHash)
        """
        result = self._cast_send(
            "commit(bytes32,bytes32)",
            [record.task_id, record.commit_hash],
        )

        if result["success"]:
            record.tx_hash = result.get("tx_hash", "")
            self._save_commit(record)
        else:
            raise RuntimeError(f"Commit tx failed: {result.get('error', 'unknown')}")

        return record

    # ── Reveal Phase ─────────────────────────────────────────────────────

    def reveal(self, task_id: str) -> RevealResult:
        """
        Reveal a previously committed exploit.

        Loads the saved commit record, then calls:
        CommitReveal.reveal(bytes32 taskId, bytes32 exploitArtifactHash, bytes32 nonce)
        """
        record = self._load_commit(task_id)
        if record is None:
            return RevealResult(
                success=False,
                task_id=task_id,
                exploit_artifact_hash="",
                error="No commit record found for this task",
            )

        if record.revealed:
            return RevealResult(
                success=False,
                task_id=task_id,
                exploit_artifact_hash=record.exploit_artifact_hash,
                error="Already revealed",
            )

        result = self._cast_send(
            "reveal(bytes32,bytes32,bytes32)",
            [record.task_id, record.exploit_artifact_hash, record.nonce],
        )

        if result["success"]:
            record.revealed = True
            record.reveal_tx_hash = result.get("tx_hash", "")
            self._save_commit(record)

            # Check who was the earliest committer
            earliest = self._get_earliest_reveal(
                task_id, record.exploit_artifact_hash
            )

            return RevealResult(
                success=True,
                task_id=task_id,
                exploit_artifact_hash=record.exploit_artifact_hash,
                tx_hash=result.get("tx_hash", ""),
                earliest_committer=earliest,
            )
        else:
            return RevealResult(
                success=False,
                task_id=task_id,
                exploit_artifact_hash=record.exploit_artifact_hash,
                error=result.get("error", "Reveal tx failed"),
            )

    # ── Query Functions ──────────────────────────────────────────────────

    def is_commit_window_open(self, task_id: str) -> bool:
        """Check if the commit window is currently open for a task."""
        result = self._cast_call(
            "isCommitWindowOpen(bytes32)(bool)",
            [task_id],
        )
        return result.strip().lower() == "true"

    def is_reveal_window_open(self, task_id: str) -> bool:
        """Check if the reveal window is currently open for a task."""
        result = self._cast_call(
            "isRevealWindowOpen(bytes32)(bool)",
            [task_id],
        )
        return result.strip().lower() == "true"

    def get_commit_count(self, task_id: str) -> int:
        """Get the number of commitments for a task."""
        result = self._cast_call(
            "commitCount(bytes32)(uint256)",
            [task_id],
        )
        return int(result.strip())

    def has_committed(self, task_id: str) -> bool:
        """Check if this miner has already committed for a task."""
        result = self._cast_call(
            "hasCommitted(bytes32,address)(bool)",
            [task_id, self.miner_address],
        )
        return result.strip().lower() == "true"

    # ── Admin Functions (Validator Only) ─────────────────────────────────

    def open_task(self, task_id: str) -> str:
        """Open a task for commit submissions (validator/owner only)."""
        result = self._cast_send(
            "openTask(bytes32)",
            [task_id],
        )
        if not result["success"]:
            raise RuntimeError(f"openTask failed: {result.get('error', '')}")
        return result.get("tx_hash", "")

    # ── Hashing Utilities ────────────────────────────────────────────────

    @staticmethod
    def _keccak256_hex(data: bytes) -> str:
        """Compute keccak256 and return as 0x-prefixed hex bytes32."""
        # Primary: use pycryptodome's Keccak (matches Solidity exactly)
        try:
            from Crypto.Hash import keccak as _keccak
            k = _keccak.new(digest_bits=256)
            k.update(data)
            return "0x" + k.hexdigest()
        except ImportError:
            pass

        # Fallback: use Foundry's `cast keccak` CLI
        try:
            result = subprocess.run(
                ["cast", "keccak", "0x" + data.hex()],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip().startswith("0x"):
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        raise RuntimeError(
            "Cannot compute Ethereum keccak256: install pycryptodome "
            "(pip install pycryptodome) or ensure `cast` is on PATH"
        )

    @staticmethod
    def _compute_commit_hash(task_id: str, artifact_hash: str, nonce: str) -> str:
        """
        Compute commit hash matching Solidity's:
        keccak256(abi.encodePacked(taskId, exploitArtifactHash, nonce))
        """
        packed_bytes = bytes.fromhex(task_id[2:] + artifact_hash[2:] + nonce[2:])

        # Primary: pycryptodome keccak
        try:
            from Crypto.Hash import keccak as _keccak
            k = _keccak.new(digest_bits=256)
            k.update(packed_bytes)
            return "0x" + k.hexdigest()
        except ImportError:
            pass

        # Fallback: cast keccak CLI
        try:
            result = subprocess.run(
                ["cast", "keccak", f"0x{packed_bytes.hex()}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip().startswith("0x"):
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        raise RuntimeError(
            "Cannot compute Ethereum keccak256: install pycryptodome or ensure `cast` on PATH"
        )

    # ── On-chain Interaction Helpers ─────────────────────────────────────

    def _cast_send(self, sig: str, args: list) -> dict:
        """Send a transaction via cast send."""
        env = os.environ.copy()

        cmd = [
            "cast", "send",
            "--rpc-url", self.rpc_url,
            self.contract_address,
            sig,
        ] + [str(a) for a in args]

        # Auth: prefer --unlocked (Anvil) if no private key, otherwise use
        # env var so the key never appears in `ps aux`.
        if self.private_key:
            env["ETH_PRIVATE_KEY"] = self.private_key
            # cast reads ETH_PRIVATE_KEY from environment natively — no CLI flag needed.
        elif self.miner_address:
            cmd.extend(["--from", self.miner_address, "--unlocked"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, env=env,
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            # Parse tx hash from cast output
            tx_hash = ""
            for line in result.stdout.split("\n"):
                if "transactionHash" in line:
                    tx_hash = line.split()[-1].strip()
                    break

            return {"success": True, "tx_hash": tx_hash, "stdout": result.stdout}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}

    def _cast_call(self, sig: str, args: list) -> str:
        """Call a view function via cast call."""
        cmd = [
            "cast", "call",
            "--rpc-url", self.rpc_url,
            self.contract_address,
            sig,
        ] + [str(a) for a in args]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(f"cast call failed: {result.stderr}")
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"cast call error: {e}")

    def _get_earliest_reveal(self, task_id: str, artifact_hash: str) -> str:
        """Query the earliest revealed commitment for an artifact hash."""
        try:
            result = self._cast_call(
                "getEarliestReveal(bytes32,bytes32)(address,uint256)",
                [task_id, artifact_hash],
            )
            # Result format: "address\nuint256"
            lines = result.strip().split("\n")
            if lines:
                return lines[0].strip()
        except RuntimeError:
            pass
        return ""

    # ── Local Persistence ────────────────────────────────────────────────

    def _save_commit(self, record: CommitRecord):
        """Save commit record to local disk (needed for reveal phase)."""
        filename = f"commit_{record.task_id[:18]}.json"
        path = self.data_dir / filename
        path.write_text(json.dumps(record.to_dict(), indent=2))

    def _load_commit(self, task_id: str) -> Optional[CommitRecord]:
        """Load a previously saved commit record."""
        filename = f"commit_{task_id[:18]}.json"
        path = self.data_dir / filename
        if not path.exists():
            # Try prefix match
            for f in self.data_dir.glob("commit_*.json"):
                data = json.loads(f.read_text())
                if data.get("task_id", "").startswith(task_id):
                    return CommitRecord.from_dict(data)
            return None
        return CommitRecord.from_dict(json.loads(path.read_text()))

    def list_commits(self) -> list[CommitRecord]:
        """List all saved commit records."""
        records = []
        for f in sorted(self.data_dir.glob("commit_*.json")):
            data = json.loads(f.read_text())
            records.append(CommitRecord.from_dict(data))
        return records


# ── Simulation Mode ──────────────────────────────────────────────────────────

class CommitRevealSimulator:
    """
    In-memory commit-reveal simulator for testing without a live chain.

    Mirrors CommitReveal.sol logic but runs entirely in Python.
    """

    def __init__(self):
        self.tasks: dict[str, float] = {}       # taskId → open timestamp
        self.commits: dict[str, list] = {}       # taskId → [CommitRecord]
        self.miner_commits: dict[str, dict] = {} # taskId → {miner → idx}

        self.COMMIT_WINDOW = 2 * 3600   # 2 hours
        self.REVEAL_WINDOW = 4 * 3600   # 4 hours

    def open_task(self, task_id: str, timestamp: float = None):
        if timestamp is None:
            timestamp = time.time()
        self.tasks[task_id] = timestamp
        self.commits.setdefault(task_id, [])
        self.miner_commits.setdefault(task_id, {})

    def commit(
        self,
        task_id: str,
        miner: str,
        exploit_source: str,
        timestamp: float = None,
    ) -> CommitRecord:
        if timestamp is None:
            timestamp = time.time()

        if task_id not in self.tasks:
            raise ValueError("Task not open")

        open_time = self.tasks[task_id]
        if timestamp > open_time + self.COMMIT_WINDOW:
            raise ValueError("Commit window closed")

        if miner in self.miner_commits.get(task_id, {}):
            raise ValueError("Already committed")

        artifact_hash = CommitRevealClient._keccak256_hex(exploit_source.encode())
        nonce = "0x" + secrets.token_hex(32)

        # Compute commit hash matching on-chain keccak256(abi.encodePacked(...))
        commit_hash = CommitRevealClient._compute_commit_hash(task_id, artifact_hash, nonce)

        record = CommitRecord(
            task_id=task_id,
            exploit_artifact_hash=artifact_hash,
            nonce=nonce,
            commit_hash=commit_hash,
            committed_at=timestamp,
        )

        idx = len(self.commits[task_id])
        self.commits[task_id].append(record)
        self.miner_commits[task_id][miner] = idx

        return record

    def reveal(
        self,
        task_id: str,
        miner: str,
        record: CommitRecord,
        timestamp: float = None,
    ) -> RevealResult:
        if timestamp is None:
            timestamp = time.time()

        if task_id not in self.tasks:
            return RevealResult(False, task_id, "", error="Task not open")

        open_time = self.tasks[task_id]
        if timestamp < open_time + self.COMMIT_WINDOW:
            return RevealResult(False, task_id, "", error="Reveal window not open yet")
        if timestamp > open_time + self.COMMIT_WINDOW + self.REVEAL_WINDOW:
            return RevealResult(False, task_id, "", error="Reveal window closed")

        idx = self.miner_commits.get(task_id, {}).get(miner)
        if idx is None:
            return RevealResult(False, task_id, "", error="No commitment found")

        stored = self.commits[task_id][idx]
        if stored.revealed:
            return RevealResult(False, task_id, "", error="Already revealed")

        # Verify hash matches (using same keccak256 as commit phase)
        expected = CommitRevealClient._compute_commit_hash(
            record.task_id, record.exploit_artifact_hash, record.nonce
        )
        if expected != stored.commit_hash:
            return RevealResult(False, task_id, "", error="Invalid reveal — hash mismatch")

        stored.revealed = True
        stored.exploit_artifact_hash = record.exploit_artifact_hash

        return RevealResult(
            success=True,
            task_id=task_id,
            exploit_artifact_hash=record.exploit_artifact_hash,
            earliest_committer=miner,
        )

    def get_earliest_reveal(self, task_id: str, artifact_hash: str) -> tuple[str, float]:
        """Find the earliest commitment for a given artifact hash."""
        earliest_time = float("inf")
        earliest_miner = ""
        for miner, idx in self.miner_commits.get(task_id, {}).items():
            record = self.commits[task_id][idx]
            if (record.revealed and
                record.exploit_artifact_hash == artifact_hash and
                record.committed_at < earliest_time):
                earliest_time = record.committed_at
                earliest_miner = miner
        return earliest_miner, earliest_time
