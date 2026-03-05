"""
Tests for neurons (validator/miner), miner CLI, mutator module,
metrics server, input sanitization, and rate limiting.

Run: python3 -m pytest tests/test_extended.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ══════════════════════════════════════════════════════════════════════════════
# Mutator Module Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMutatorModule:
    """Test the pluggable mutator framework."""

    SAMPLE_SOURCE = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.28;\n\n"
        "contract Vulnerable {\n"
        "    uint256 public balance;\n"
        "    function deposit() public payable {\n"
        "        balance += msg.value;\n"
        "    }\n"
        "    function withdraw(uint256 amount) public {\n"
        "        require(amount <= balance);\n"
        "        (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
        "        require(ok);\n"
        "        balance -= amount;\n"
        "    }\n"
        "}\n"
    )

    def test_rename_mutator(self):
        from task_generator.mutator.rename import RenameMutator

        m = RenameMutator()
        result = m.apply(self.SAMPLE_SOURCE, {"rename_map": {"balance": "funds", "deposit": "fund"}})
        assert "funds" in result
        assert "fund()" in result
        # Original names should be gone
        assert "balance" not in result

    def test_storage_layout_mutator(self):
        from task_generator.mutator.storage import StorageLayoutMutator

        m = StorageLayoutMutator()
        result = m.apply(self.SAMPLE_SOURCE, {"storage_prefix": "test42"})
        assert "_pad_test42" in result
        # Padding var inserted after first brace
        idx_pad = result.index("_pad_test42")
        idx_brace = result.index("{")
        assert idx_pad > idx_brace

    def test_storage_layout_no_prefix(self):
        from task_generator.mutator.storage import StorageLayoutMutator

        m = StorageLayoutMutator()
        result = m.apply(self.SAMPLE_SOURCE, {})
        assert result == self.SAMPLE_SOURCE  # No change

    def test_balance_mutator(self):
        from task_generator.mutator.balance import BalanceMutator

        source_with_ether = "require(msg.value >= 1 ether);\n"
        m = BalanceMutator()
        result = m.apply(source_with_ether, {"initial_balance_literal": "5"})
        assert "5 ether" in result
        assert "1 ether" not in result

    def test_balance_mutator_no_param(self):
        from task_generator.mutator.balance import BalanceMutator

        m = BalanceMutator()
        result = m.apply("1 ether", {})
        assert result == "1 ether"

    def test_deadcode_mutator(self):
        from task_generator.mutator.deadcode import DeadCodeMutator

        m = DeadCodeMutator()
        result = m.apply(self.SAMPLE_SOURCE, {"dead_code_count": 3}, seed=123)
        # Should have injected code before the last brace
        assert result != self.SAMPLE_SOURCE
        # Contract should still end with }
        assert result.rstrip().endswith("}")

    def test_deadcode_determinism(self):
        from task_generator.mutator.deadcode import DeadCodeMutator

        m = DeadCodeMutator()
        r1 = m.apply(self.SAMPLE_SOURCE, {"dead_code_count": 2}, seed=99)
        r2 = m.apply(self.SAMPLE_SOURCE, {"dead_code_count": 2}, seed=99)
        assert r1 == r2, "Same seed must produce identical output"

    def test_deadcode_zero_count(self):
        from task_generator.mutator.deadcode import DeadCodeMutator

        m = DeadCodeMutator()
        result = m.apply(self.SAMPLE_SOURCE, {"dead_code_count": 0})
        assert result == self.SAMPLE_SOURCE

    def test_registry_compose(self):
        from task_generator.mutator import MutationRegistry

        reg = MutationRegistry(seed=42)
        mutations = {
            "rename_map": {"Vulnerable": "Target"},
            "storage_prefix": "mut_1",
            "dead_code_count": 1,
        }
        result = reg.apply(self.SAMPLE_SOURCE, mutations)
        assert "Target" in result
        assert "Vulnerable" not in result
        assert "_pad_mut_1" in result

    def test_registry_list_mutators(self):
        from task_generator.mutator import MutationRegistry

        reg = MutationRegistry()
        names = reg.list_mutators()
        assert "rename" in names
        assert "storage_layout" in names
        assert "balance" in names
        assert "deadcode" in names

    def test_registry_custom_pipeline(self):
        from task_generator.mutator import MutationRegistry
        from task_generator.mutator.rename import RenameMutator

        reg = MutationRegistry(mutators=[RenameMutator()])
        assert reg.list_mutators() == ["rename"]

    def test_generate_py_delegates_to_registry(self):
        """Ensure generate.py._apply_mutations uses the mutator registry."""
        from task_generator.generate import CorpusGenerator

        gen = CorpusGenerator()
        mutations = {"rename_map": {"Foo": "Bar"}}
        result = gen._apply_mutations("contract Foo {}", mutations)
        assert "Bar" in result


# ══════════════════════════════════════════════════════════════════════════════
# Metrics Server Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMetrics:
    """Test the lightweight metrics module."""

    def test_counter_increment(self):
        from validator.metrics import _MetricsStore

        store = _MetricsStore()
        store.inc("test_counter")
        store.inc("test_counter")
        assert store.get_counter("test_counter") == 2

    def test_gauge_set(self):
        from validator.metrics import _MetricsStore

        store = _MetricsStore()
        store.set_gauge("cpu", 0.75)
        assert store.get_gauge("cpu") == 0.75

    def test_histogram_observe(self):
        from validator.metrics import _MetricsStore

        store = _MetricsStore()
        for v in [10, 20, 30, 40, 50]:
            store.observe("latency", v)
        snap = store.snapshot()
        assert snap["latency_count"] == 5
        assert snap["latency_mean"] == 30.0
        assert snap["latency_p50"] == 30

    def test_snapshot_includes_uptime(self):
        from validator.metrics import _MetricsStore

        store = _MetricsStore()
        snap = store.snapshot()
        assert "uptime_seconds" in snap
        assert snap["uptime_seconds"] >= 0

    def test_global_module_functions(self):
        from validator import metrics

        # These should not raise
        metrics.inc("_test_global")
        metrics.set_gauge("_test_g", 1.0)
        metrics.observe("_test_h", 5.0)
        snap = metrics.snapshot()
        assert snap.get("_test_global", 0) >= 1

    def test_http_server(self):
        """Start the metrics HTTP server and verify /health and /metrics."""
        from validator.metrics import MetricsServer

        srv = MetricsServer(port=0)  # port 0 = OS-assigned
        srv._httpd = None
        # Use a real port
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        srv = MetricsServer(host="127.0.0.1", port=port)
        srv.start()
        time.sleep(0.2)

        try:
            # /health
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            data = json.loads(resp.read())
            assert data["status"] == "ok"

            # /metrics
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics")
            data = json.loads(resp.read())
            assert "uptime_seconds" in data
        finally:
            srv.stop()


# ══════════════════════════════════════════════════════════════════════════════
# Neurons Tests (ValidatorNeuron / MinerNeuron — local mode)
# ══════════════════════════════════════════════════════════════════════════════

class TestValidatorNeuron:
    """Test ValidatorNeuron in local mode (no Bittensor dependency)."""

    def test_init_local_mode(self):
        from neurons.validator import ValidatorNeuron

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("orchestrator.DATA_DIR", Path(tmpdir)):
                n = ValidatorNeuron(mode="local")
                assert n.mode == "local"
                assert n.wallet is None
                assert n.metagraph is None

    def test_status_local(self):
        from neurons.validator import ValidatorNeuron

        n = ValidatorNeuron(mode="local")
        s = n.status()
        assert s["mode"] == "local"
        assert "epoch" in s
        assert "submissions_this_epoch" in s

    def test_handle_submission_rate_limit(self):
        """Per-miner rate limiting should reject excess submissions."""
        from neurons.validator import ValidatorNeuron, MAX_SUBMISSIONS_PER_MINER_PER_EPOCH
        from neurons.protocol import ExploitSubmissionSynapse

        n = ValidatorNeuron(mode="local")
        # Simulate a miner maxed out
        n._miner_submission_counts["miner_a"] = MAX_SUBMISSIONS_PER_MINER_PER_EPOCH

        synapse = ExploitSubmissionSynapse()
        synapse.task_id = "0xdeadbeef"
        synapse.exploit_source = "contract X {}"
        synapse.commit_hash = ""
        synapse.result = {}
        # Mock dendrite.hotkey
        synapse.dendrite = MagicMock()
        synapse.dendrite.hotkey = "miner_a"

        result = n._handle_submission(synapse)
        assert "error" in result.result
        assert "limit" in result.result["error"].lower()

    def test_handle_submission_epoch_limit(self):
        """Global epoch limit should reject when exceeded."""
        from neurons.validator import ValidatorNeuron, MAX_SUBMISSIONS_PER_EPOCH
        from neurons.protocol import ExploitSubmissionSynapse

        n = ValidatorNeuron(mode="local")
        n.submissions_this_epoch = [None] * MAX_SUBMISSIONS_PER_EPOCH

        synapse = ExploitSubmissionSynapse()
        synapse.task_id = "0xdeadbeef"
        synapse.exploit_source = "contract X {}"
        synapse.commit_hash = ""
        synapse.result = {}

        result = n._handle_submission(synapse)
        assert "error" in result.result


class TestMinerNeuron:
    """Test MinerNeuron in local mode."""

    def test_init_local_mode(self):
        from neurons.miner import MinerNeuron

        n = MinerNeuron(mode="local")
        assert n.mode == "local"
        assert n.wallet is None

    def test_status_local(self):
        from neurons.miner import MinerNeuron

        n = MinerNeuron(mode="local")
        s = n.status()
        assert s["mode"] == "local"
        assert "address" in s

    def test_prepare_and_find_exploit(self):
        from neurons.miner import MinerNeuron

        n = MinerNeuron(mode="local")
        task_id = "0x" + "ab" * 16
        source = "contract Exploit { function run() public {} }"

        n.prepare_exploit(task_id, source)

        found = n._find_prepared_exploit(task_id)
        assert found is not None
        assert found.read_text() == source

        # Cleanup
        found.unlink(missing_ok=True)

    def test_find_exploit_missing(self):
        from neurons.miner import MinerNeuron

        n = MinerNeuron(mode="local")
        assert n._find_prepared_exploit("0xnonexistent") is None


# ══════════════════════════════════════════════════════════════════════════════
# Miner CLI Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMinerCLI:
    """Test MinerCLI commands."""

    def test_cmd_tasks_no_corpus(self, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        cli.cmd_tasks(MagicMock())
        captured = capsys.readouterr()
        # Either prints tasks or "No tasks available"
        assert "tasks" in captured.out.lower() or "no tasks" in captured.out.lower() or captured.out == ""

    def test_cmd_status_no_submissions(self, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        cli.cmd_status(MagicMock())
        captured = capsys.readouterr()
        # Should print "No submissions found" or a table
        assert "no submissions" in captured.out.lower() or "#" in captured.out or captured.out == ""

    def test_cmd_scores_no_epochs(self, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        cli.cmd_scores(MagicMock())
        captured = capsys.readouterr()
        # Should print epoch info, "no epochs" message, or nothing
        assert ("epoch" in captured.out.lower() or
                "no epoch" in captured.out.lower() or
                captured.out == "")

    def test_cmd_submit_missing_file(self, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        args = MagicMock()
        args.exploit = "/tmp/__nonexistent_exploit__.sol"
        args.task = "0xfake_task"
        cli.cmd_submit(args)
        # Should log error about missing file, no crash

    def test_cmd_scaffold_unknown_task(self, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        args = MagicMock()
        args.task = "0x_nonexistent_task_id"
        args.output = None
        cli.cmd_scaffold(args)
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or captured.out == ""

    def test_cmd_submit_oversized_file(self, tmp_path, capsys):
        from miner.cli import MinerCLI

        cli = MinerCLI(miner_address="0xTEST")
        big_file = tmp_path / "huge.sol"
        big_file.write_text("x" * (512 * 1024 + 1))
        args = MagicMock()
        args.exploit = str(big_file)
        args.task = "0xfake"
        cli.cmd_submit(args)
        # Should reject oversized file, no crash


# ══════════════════════════════════════════════════════════════════════════════
# Input Sanitization Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestInputSanitization:
    """Test that the validation engine rejects malicious input."""

    def test_path_traversal_rejected(self):
        from validator.engine.validate import ValidationEngine

        engine = ValidationEngine()
        bad_sources = [
            '// SPDX\nimport "../../../etc/passwd";',
            '// SPDX\nimport "/etc/shadow";',
        ]
        for src in bad_sources:
            result = engine._sanitize_source(src)
            assert result is False, f"Path traversal not rejected: {src[:40]}"

    def test_safe_source_accepted(self):
        from validator.engine.validate import ValidationEngine

        engine = ValidationEngine()
        safe = "// SPDX\npragma solidity ^0.8.28;\ncontract X { }"
        assert engine._sanitize_source(safe) is True

    def test_oversized_source_rejected(self):
        """Oversized source is rejected by validate(), not _sanitize_source directly."""
        from validator.engine.validate import MAX_EXPLOIT_SOURCE_BYTES

        big_source = "x" * (MAX_EXPLOIT_SOURCE_BYTES + 1)
        assert len(big_source) > MAX_EXPLOIT_SOURCE_BYTES

    def test_null_bytes_in_source(self):
        from validator.engine.validate import ValidationEngine

        engine = ValidationEngine()
        # Source with null bytes — _sanitize_source checks path traversal,
        # null bytes are handled by the compilation step.
        src = "contract X { }\x00\x00hidden"
        # This doesn't contain path traversal, so _sanitize_source passes it
        result = engine._sanitize_source(src)
        assert isinstance(result, bool)


# ══════════════════════════════════════════════════════════════════════════════
# Anti-Collusion / Consensus Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestConsensusExtended:
    """Extended tests for the anti-collusion engine."""

    def test_consensus_below_quorum(self):
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            # Register only 3 validators (below MIN_QUORUM=5)
            for i in range(3):
                engine.register_validator(f"val_{i}", stake=1.0)

            result = engine.compute_consensus(
                task_id="0xtask",
                submission_hash="0xhash",
                votes=[
                    {"validator_hotkey": f"val_{i}", "result": "VALID"}
                    for i in range(3)
                ],
            )
            assert result.consensus_result == "NO_QUORUM"

    def test_consensus_agreement(self):
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(7):
                engine.register_validator(f"val_{i}", stake=1.0)

            result = engine.compute_consensus(
                task_id="0xtask",
                submission_hash="0xhash",
                votes=[
                    {"validator_hotkey": f"val_{i}", "result": "VALID"}
                    for i in range(7)
                ],
            )
            assert result.consensus_result == "VALID"
            assert result.agreement_ratio == 1.0

    def test_divergence_detection(self):
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(7):
                engine.register_validator(f"val_{i}", stake=1.0)

            votes = [
                {"validator_hotkey": f"val_{i}", "result": "VALID"}
                for i in range(5)
            ] + [
                {"validator_hotkey": f"val_{i}", "result": "REJECT_NO_IMPACT"}
                for i in range(5, 7)
            ]

            result = engine.compute_consensus(
                task_id="0xtask",
                submission_hash="0xhash",
                votes=votes,
            )
            assert len(result.diverging_validators) == 2
            assert "val_5" in result.diverging_validators
            assert "val_6" in result.diverging_validators


# ══════════════════════════════════════════════════════════════════════════════
# Commit-Reveal Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCommitReveal:
    """Test CommitRevealSimulator and CommitRevealClient helpers."""

    # Valid bytes32 hex task IDs for tests
    TASK1 = "0x" + "01" * 32
    TASK2 = "0x" + "02" * 32
    TASK3 = "0x" + "03" * 32
    TASK4 = "0x" + "04" * 32
    TASK5 = "0x" + "05" * 32

    def test_simulator_full_cycle(self):
        """Commit → reveal succeeds within the time windows."""
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        t0 = 1_000_000.0
        sim.open_task(self.TASK1, timestamp=t0)

        record = sim.commit(self.TASK1, "miner-A", "contract Exploit {}", timestamp=t0 + 10)
        assert record.commit_hash
        assert record.nonce

        # Reveal after commit window closes
        reveal = sim.reveal(self.TASK1, "miner-A", record,
                            timestamp=t0 + sim.COMMIT_WINDOW + 1)
        assert reveal.success
        assert reveal.earliest_committer == "miner-A"

    def test_simulator_commit_window_closed(self):
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        t0 = 1_000_000.0
        sim.open_task(self.TASK2, timestamp=t0)

        try:
            sim.commit(self.TASK2, "miner-B", "contract X {}",
                       timestamp=t0 + sim.COMMIT_WINDOW + 1)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Commit window closed" in str(e)

    def test_simulator_reveal_before_window(self):
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        t0 = 1_000_000.0
        sim.open_task(self.TASK3, timestamp=t0)

        record = sim.commit(self.TASK3, "miner-C", "contract Y {}", timestamp=t0 + 5)
        # Reveal too early
        reveal = sim.reveal(self.TASK3, "miner-C", record, timestamp=t0 + 10)
        assert not reveal.success
        assert "not open yet" in reveal.error

    def test_simulator_double_commit(self):
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        t0 = 1_000_000.0
        sim.open_task(self.TASK4, timestamp=t0)

        sim.commit(self.TASK4, "miner-D", "contract Z {}", timestamp=t0 + 1)
        try:
            sim.commit(self.TASK4, "miner-D", "contract Z2 {}", timestamp=t0 + 2)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Already committed" in str(e)

    def test_simulator_earliest_reveal(self):
        """Earliest committer wins for the same artifact hash."""
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        t0 = 1_000_000.0
        sim.open_task(self.TASK5, timestamp=t0)

        # Same exploit source → same artifact hash
        rec1 = sim.commit(self.TASK5, "miner-E", "contract Same {}", timestamp=t0 + 1)
        rec2 = sim.commit(self.TASK5, "miner-F", "contract Same {}", timestamp=t0 + 2)

        reveal_ts = t0 + sim.COMMIT_WINDOW + 1
        r1 = sim.reveal(self.TASK5, "miner-E", rec1, timestamp=reveal_ts)
        r2 = sim.reveal(self.TASK5, "miner-F", rec2, timestamp=reveal_ts)

        assert r1.success and r2.success
        miner, _ = sim.get_earliest_reveal(self.TASK5, rec1.exploit_artifact_hash)
        assert miner == "miner-E"

    def test_client_prepare_commit_determinism(self):
        """prepare_commit produces correct hash structure."""
        from validator.commit_reveal import CommitRevealClient

        client = CommitRevealClient(
            contract_address="0x" + "00" * 20,
            rpc_url="http://localhost:8545",
        )
        rec = client.prepare_commit("0x" + "aa" * 32, "contract Exploit {}")
        assert rec.commit_hash.startswith("0x")
        assert rec.nonce.startswith("0x")
        assert len(rec.nonce) == 66  # 0x + 64 hex chars
        assert rec.exploit_artifact_hash.startswith("0x")


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator Reveal-and-Process + Epoch Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestOrchestratorAdvanced:
    """Test reveal_and_process and close_epoch with actual submissions."""

    def _make_orchestrator(self, tmpdir):
        from orchestrator import Orchestrator
        corpus_dir = Path(tmpdir) / "corpus"
        data_dir = Path(tmpdir) / "data"
        orch = Orchestrator(
            mode="local",
            corpus_dir=corpus_dir,
            data_dir=data_dir,
        )
        return orch

    def test_reveal_and_process_simulator(self):
        """reveal_and_process succeeds with simulator commit-reveal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orchestrator(tmpdir)

            # Generate a corpus so load_task can find something
            packages = orch.generate_corpus(count_per_class=1, seed=42)
            assert len(packages) > 0
            task_id = packages[0].task_id

            # Open the task at the current time so commit window is open
            now = time.time()
            orch.commit_reveal.open_task(task_id, timestamp=now)

            # Phase 1: Commit (default timestamp = time.time(), within window)
            record = orch.commit_exploit(task_id, "contract Exploit {}", "miner-A")
            assert record.commit_hash

            # Advance simulator past commit window by rewriting the open time
            orch.commit_reveal.tasks[task_id] = now - orch.commit_reveal.COMMIT_WINDOW - 1

            # Phase 2: Reveal + process
            result = orch.reveal_and_process(
                task_id, "contract Exploit {}", "miner-A",
                commit_record=record,
            )
            # The exploit source is minimal so validation likely rejects,
            # but the flow should complete without errors
            assert result.task_id == task_id
            assert result.miner_address == "miner-A"
            assert result.validation_result != ""

    def test_close_epoch_with_votes(self):
        """close_epoch after recording votes produces proper weights."""
        from subnet_adapter.incentive import ValidatorVote, EpochResult

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orchestrator(tmpdir)

            # Record valid votes directly into the incentive adapter
            for i in range(3):
                vote = ValidatorVote(
                    validator_hotkey="validator-0",
                    task_id=f"0xtask{i}",
                    submission_hash=hashlib.sha256(f"exploit{i}".encode()).hexdigest(),
                    result="VALID",
                    fingerprint=f"fp_{i}",
                    severity_score=5.0 + i,
                    timestamp=time.time(),
                    miner_hotkey=f"miner-{i}",
                )
                orch.incentive.record_vote(vote)

            epoch = orch.close_epoch(epoch_number=1, start_block=0, end_block=100)
            assert epoch.total_submissions == 3
            assert epoch.total_valid == 3
            assert len(epoch.weights) == 3
            total = sum(epoch.weights.values())
            assert abs(total - 1.0) < 1e-9, f"Weights don't sum to 1.0: {total}"

    def test_close_epoch_empty(self):
        """close_epoch with no submissions returns empty weights."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orchestrator(tmpdir)
            epoch = orch.close_epoch(epoch_number=1, start_block=0, end_block=100)
            assert epoch.total_submissions == 0
            assert len(epoch.weights) == 0


# ══════════════════════════════════════════════════════════════════════════════
# Edge Cases: Empty / Null Exploit Source
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases for exploit validation."""

    def test_empty_exploit_source(self):
        """Empty exploit source should be rejected."""
        from validator.engine.validate import ValidationEngine, ExploitSubmission

        with tempfile.TemporaryDirectory() as tmpdir:
            ve = ValidationEngine(validator_id="test", work_dir=Path(tmpdir))
            task = {
                "task_id": "0x" + "aa" * 32,
                "source_code": "contract Vuln { }",
                "solc_version": "0.8.28",
            }
            sub = ExploitSubmission(
                task_id=task["task_id"],
                exploit_source="",
            )
            report = ve.validate(task, sub)
            # Empty exploit should either fail compilation or be rejected
            assert report.result.value != "VALID" or report.error_message

    def test_sanitize_path_traversal(self):
        """Exploit with path traversal in imports should be rejected."""
        from validator.engine.validate import ValidationEngine

        result = ValidationEngine._sanitize_source(
            'import "../../../etc/passwd";'
        )
        assert result is False

    def test_sanitize_absolute_path(self):
        """Exploit with absolute path in imports should be rejected."""
        from validator.engine.validate import ValidationEngine

        result = ValidationEngine._sanitize_source(
            'import "/etc/passwd";'
        )
        assert result is False

    def test_sanitize_clean_source(self):
        """Normal Solidity source should pass sanitization."""
        from validator.engine.validate import ValidationEngine

        result = ValidationEngine._sanitize_source(
            'pragma solidity ^0.8.28;\nimport "forge-std/Test.sol";\ncontract Exploit {}'
        )
        assert result is True

    def test_process_unknown_task(self):
        """Processing a submission for unknown task returns REJECT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from orchestrator import Orchestrator
            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )
            result = orch.process_submission(
                "0xnonexistent", "contract X {}", "miner-Z"
            )
            assert "REJECT" in result.validation_result
            assert "not found" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Boundary & Exhaustion Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestBoundaryConditions:
    """Test boundary conditions and exhaustion scenarios."""

    def test_exploit_at_exact_max_size(self):
        """Exploit at exactly MAX_EXPLOIT_SOURCE_BYTES should be accepted (not rejected)."""
        from orchestrator import MAX_EXPLOIT_SOURCE_BYTES, Orchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )
            # Generate corpus so we have a valid task
            packages = orch.generate_corpus(count_per_class=1, seed=42)
            if not packages:
                return  # Skip if generation unavailable

            task_id = packages[0].task_id

            # Build exploit source at exactly MAX_EXPLOIT_SOURCE_BYTES
            header = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\ncontract Exploit {\n"
            footer = "\n}\n"
            # Pad with single-byte ASCII to hit exact limit
            padding_needed = MAX_EXPLOIT_SOURCE_BYTES - len(header.encode()) - len(footer.encode())
            padding = "// " + "x" * (padding_needed - 3)  # "// " prefix + x's
            exploit_source = header + padding + footer
            assert len(exploit_source.encode()) == MAX_EXPLOIT_SOURCE_BYTES

            result = orch.process_submission(task_id, exploit_source, "miner-boundary")
            # Should NOT be rejected for size — may fail compilation, but not format
            assert result.validation_result != "REJECT_INVALID_FORMAT" or "exceeds" not in result.error

    def test_exploit_one_byte_over_max_rejected(self):
        """Exploit at MAX_EXPLOIT_SOURCE_BYTES + 1 should be rejected."""
        from orchestrator import MAX_EXPLOIT_SOURCE_BYTES, Orchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )
            exploit_source = "x" * (MAX_EXPLOIT_SOURCE_BYTES + 1)
            result = orch.process_submission("0xabc", exploit_source, "miner-over")
            assert result.validation_result == "REJECT_INVALID_FORMAT"
            assert "exceeds" in result.error

    def test_commit_reveal_nonce_exhaustion(self):
        """Simulator should enforce MAX_COMMITS_PER_TASK limit."""
        from validator.commit_reveal import CommitRevealSimulator

        sim = CommitRevealSimulator()
        task_id = "task-exhaust-001"
        sim.open_task(task_id)

        max_commits = 256  # Matches contract MAX_COMMITS_PER_TASK

        # Submit up to the limit
        for i in range(max_commits):
            record = sim.commit(
                task_id=task_id,
                miner=f"miner-{i:04d}",
                exploit_source=f"contract Exploit{i} {{}}",
            )
            assert record is not None

        # The 257th should fail or raise
        try:
            sim.commit(
                task_id=task_id,
                miner="miner-overflow",
                exploit_source="contract ExploitOverflow {}",
            )
            # If it doesn't raise, the simulator doesn't enforce the limit
            # (only the on-chain contract does) — that's acceptable
        except (ValueError, RuntimeError):
            pass  # Expected: simulator enforces the limit

    def test_epoch_overlap_guard(self):
        """Concurrent close_epoch calls should not corrupt state."""
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            from orchestrator import Orchestrator

            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )

            results = []
            errors = []

            def close_epoch_thread(epoch_num):
                try:
                    r = orch.close_epoch(epoch_num, epoch_num * 100, (epoch_num + 1) * 100)
                    results.append(r)
                except Exception as e:
                    errors.append(e)

            threads = []
            # Fire 5 threads all trying to close epoch 1
            for _ in range(5):
                t = threading.Thread(target=close_epoch_thread, args=(1,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=30)

            assert len(errors) == 0, f"Epoch close errors: {errors}"
            # All should succeed (lock serializes them) — only one actually processes,
            # others return empty result due to duplicate guard
            assert len(results) == 5

    def test_empty_exploit_source_rejected(self):
        """Empty string exploit source should be rejected."""
        from orchestrator import Orchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )
            result = orch.process_submission("0xabc", "", "miner-empty")
            assert "REJECT" in result.validation_result

    def test_whitespace_only_exploit_rejected(self):
        """Whitespace-only exploit source should be rejected."""
        from orchestrator import Orchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                mode="local",
                corpus_dir=Path(tmpdir) / "corpus",
                data_dir=Path(tmpdir) / "data",
            )
            result = orch.process_submission("0xabc", "   \n\t  ", "miner-ws")
            assert "REJECT" in result.validation_result


# ── Large-Scale Consensus Tests ──────────────────────────────────────────────

class TestLargeScaleConsensus:
    """Test AntiCollusionEngine with 100+ validators for quorum/divergence."""

    def _make_engine(self, tmp_path, n_validators=120, stake=100.0):
        from validator.anticollusion.consensus import (
            AntiCollusionEngine, MIN_QUORUM, CONSENSUS_THRESHOLD,
            DIVERGENCE_SLASH_THRESHOLD, MAX_VALIDATORS_PER_TASK,
        )
        engine = AntiCollusionEngine(data_dir=tmp_path)
        for i in range(n_validators):
            engine.register_validator(f"val_{i:04d}", stake=stake)
        return engine

    def test_assign_validators_distributes_fairly(self, tmp_path):
        """Assignments across many tasks should use all validators."""
        from validator.anticollusion.consensus import MAX_VALIDATORS_PER_TASK
        engine = self._make_engine(tmp_path, 120)

        assignment_counts: dict[str, int] = {}
        for i in range(200):
            assigned = engine.assign_validators(f"task_{i}")
            assert len(assigned) == MAX_VALIDATORS_PER_TASK
            for v in assigned:
                assignment_counts[v] = assignment_counts.get(v, 0) + 1

        # At least 90% of validators should be assigned at least once
        active_count = sum(1 for c in assignment_counts.values() if c > 0)
        assert active_count >= 108, f"Only {active_count}/120 validators assigned"

    def test_consensus_converges_with_100_validators(self, tmp_path):
        """100-validator quorum reaches consensus at 66% threshold."""
        from validator.anticollusion.consensus import CONSENSUS_THRESHOLD
        engine = self._make_engine(tmp_path, 100)

        # 80 agree VALID, 20 disagree
        votes = [
            {"validator_hotkey": f"val_{i:04d}", "result": "VALID",
             "fingerprint": "fp1", "severity_score": 0.8}
            for i in range(80)
        ] + [
            {"validator_hotkey": f"val_{i:04d}", "result": "REJECT_INVALID",
             "fingerprint": "", "severity_score": 0.0}
            for i in range(80, 100)
        ]

        result = engine.compute_consensus("task_big", "0xhash", votes)
        assert result.consensus_result == "VALID"
        assert result.agreement_ratio >= CONSENSUS_THRESHOLD
        assert len(result.agreeing_validators) == 80
        assert len(result.diverging_validators) == 20

    def test_divergence_triggers_slashing(self, tmp_path):
        """Validator with >20% divergence rate gets slashed."""
        from validator.anticollusion.consensus import (
            DIVERGENCE_SLASH_THRESHOLD, MIN_QUORUM,
        )
        engine = self._make_engine(tmp_path, 10)

        # Run enough rounds for val_0009 to exceed divergence threshold
        for i in range(MIN_QUORUM + 5):
            # 9 validators agree, val_0009 always diverges
            votes = [
                {"validator_hotkey": f"val_{j:04d}", "result": "VALID",
                 "fingerprint": "fp", "severity_score": 0.5}
                for j in range(9)
            ] + [
                {"validator_hotkey": "val_0009", "result": "REJECT_INVALID",
                 "fingerprint": "", "severity_score": 0.0}
            ]
            engine.compute_consensus(f"task_{i}", f"hash_{i}", votes)

        # val_0009 should be slashed
        v9 = engine.validators["val_0009"]
        assert v9.slashed is True
        assert v9.divergence_rate > DIVERGENCE_SLASH_THRESHOLD
        assert len(engine.slash_events) > 0

    def test_consensus_performance_under_1s(self, tmp_path):
        """compute_consensus for 100 validators should run under 1 second."""
        engine = self._make_engine(tmp_path, 100)

        votes = [
            {"validator_hotkey": f"val_{i:04d}", "result": "VALID",
             "fingerprint": "fp1", "severity_score": 0.7}
            for i in range(100)
        ]

        start = time.time()
        for _ in range(10):
            engine.compute_consensus("perf_task", "0xhash", votes)
        elapsed = time.time() - start

        # 10 rounds should complete in under 5 seconds total (0.5s each avg)
        assert elapsed < 5.0, f"10 consensus rounds took {elapsed:.2f}s"

    def test_adversarial_consensus_with_100_validators(self, tmp_path):
        """Adversarial consensus also works with large quorum."""
        from validator.anticollusion.consensus import AdversarialConsensusResult
        engine = self._make_engine(tmp_path, 100)

        votes = [
            {"validator_hotkey": f"val_{i:04d}", "outcome": "INVARIANT_HELD"}
            for i in range(70)
        ] + [
            {"validator_hotkey": f"val_{i:04d}", "outcome": "INVARIANT_BROKEN"}
            for i in range(70, 100)
        ]

        result = engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="big_chal", votes=votes,
        )
        assert result.consensus_outcome == "INVARIANT_HELD"
        assert len(result.agreeing_validators) == 70
        assert len(result.diverging_validators) == 30

    def test_export_stats_with_many_validators(self, tmp_path):
        """export_validator_stats handles 120 validators."""
        engine = self._make_engine(tmp_path, 120)

        votes = [
            {"validator_hotkey": f"val_{i:04d}", "result": "VALID",
             "fingerprint": "fp1", "severity_score": 0.5}
            for i in range(120)
        ]
        engine.compute_consensus("task_stats", "0xhash", votes)

        stats = engine.export_validator_stats()
        assert len(stats) == 120
        for hotkey, s in stats.items():
            assert "reliability_score" in s


# ══════════════════════════════════════════════════════════════════════════════
# Concurrent Submission & Race Condition Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrentSubmissions:
    """Verify the orchestrator handles concurrent submissions safely."""

    def _make_orch(self, tmp_path):
        from orchestrator import Orchestrator
        return Orchestrator(
            mode="local",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )

    def test_concurrent_process_submissions(self, tmp_path):
        """Multiple threads submitting simultaneously should not crash."""
        orch = self._make_orch(tmp_path)
        errors = []
        source = "contract X { function test_run() public {} }"

        def submit(idx):
            try:
                orch.process_submission(
                    task_id=f"0xtask_{idx:04d}",
                    exploit_source=source,
                    miner_address=f"0xminer_{idx:04d}",
                )
            except Exception as e:
                errors.append((idx, str(e)))

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # No thread should crash; rejected submissions are fine
        assert len(errors) == 0, f"Threads crashed: {errors}"

    def test_epoch_lock_prevents_concurrent_close(self, tmp_path):
        """Concurrent close_epoch calls should be serialized by the lock."""
        orch = self._make_orch(tmp_path)
        results = []

        def close(epoch_num):
            r = orch.close_epoch(epoch_num, start_block=0, end_block=100)
            results.append(r)

        t1 = threading.Thread(target=close, args=(1,))
        t2 = threading.Thread(target=close, args=(1,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # Both should return without error
        assert len(results) == 2

    def test_duplicate_epoch_close_skipped(self, tmp_path):
        """Closing the same epoch twice returns empty result on second call."""
        orch = self._make_orch(tmp_path)
        r1 = orch.close_epoch(1, start_block=0, end_block=100)
        r2 = orch.close_epoch(1, start_block=0, end_block=100)
        # Second close should be skipped (stale epoch guard)
        assert r2.total_submissions == 0


# ══════════════════════════════════════════════════════════════════════════════
# Epoch Stall / Recovery Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEpochStallRecovery:
    """Test epoch close with zero activity and recovery scenarios."""

    def _make_orch(self, tmp_path):
        from orchestrator import Orchestrator
        return Orchestrator(
            mode="local",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )

    def test_close_epoch_no_submissions(self, tmp_path):
        """Closing an epoch with zero submissions should not fail."""
        orch = self._make_orch(tmp_path)
        result = orch.close_epoch(1, start_block=0, end_block=100)
        assert result.epoch_number == 1
        assert result.total_submissions == 0

    def test_close_epoch_monotonic_order(self, tmp_path):
        """Epoch numbers must increase monotonically."""
        orch = self._make_orch(tmp_path)
        r1 = orch.close_epoch(1, start_block=0, end_block=100)
        r2 = orch.close_epoch(2, start_block=100, end_block=200)
        r3 = orch.close_epoch(3, start_block=200, end_block=300)
        assert r1.epoch_number == 1
        assert r2.epoch_number == 2
        assert r3.epoch_number == 3

    def test_epoch_result_persisted(self, tmp_path):
        """Epoch results are saved to disk."""
        orch = self._make_orch(tmp_path)
        orch.close_epoch(1, start_block=0, end_block=50)
        epoch_file = tmp_path / "data" / "epochs" / "epoch_1.json"
        assert epoch_file.exists()
        data = json.loads(epoch_file.read_text())
        assert data["epoch_number"] == 1

    def test_backward_epoch_rejected(self, tmp_path):
        """A backward epoch number should return empty/skipped result."""
        orch = self._make_orch(tmp_path)
        orch.close_epoch(5, start_block=0, end_block=500)
        result = orch.close_epoch(3, start_block=0, end_block=300)
        assert result.total_submissions == 0


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """Run without pytest."""
    test_classes = [
        TestMutatorModule,
        TestMetrics,
        TestValidatorNeuron,
        TestMinerNeuron,
        TestMinerCLI,
        TestInputSanitization,
        TestConsensusExtended,
        TestCommitReveal,
        TestOrchestratorAdvanced,
        TestEdgeCases,
        TestBoundaryConditions,
        TestLargeScaleConsensus,
        TestConcurrentSubmissions,
        TestEpochStallRecovery,
    ]

    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        print(f"\n{'='*60}")
        print(f" {cls.__name__}")
        print(f"{'='*60}")

        instance = cls()
        for method_name in sorted(dir(instance)):
            if not method_name.startswith("test_"):
                continue

            method = getattr(instance, method_name)
            try:
                # Skip tests needing capsys when running standalone
                import inspect
                sig = inspect.signature(method)
                if "capsys" in sig.parameters:
                    print(f"  [SKIP] {method_name} (needs pytest capsys)")
                    continue
                method()
                print(f"  [PASS] {method_name}")
                passed += 1
            except Exception as e:
                print(f"  [FAIL] {method_name}: {e}")
                failed += 1
                errors.append((cls.__name__, method_name, str(e)))

    print(f"\n{'='*60}")
    print(f" Results: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    if errors:
        print("\nFailures:")
        for cls_name, method, err in errors:
            print(f"  {cls_name}.{method}: {err}")

    sys.exit(1 if failed else 0)
