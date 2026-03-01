"""
Bittensor Synapse Protocol Definitions — Exploit Subnet.

Defines the typed message format for miner ↔ validator communication
on the Bittensor network.

Two synapses:
  1. ExploitSubmissionSynapse — Miner → Validator: exploit submission
  2. ExploitQuerySynapse — Validator → Miner: task queries / heartbeats

These require the `bittensor` package at runtime. When running in local
mode (no Bittensor), a lightweight shim is used so the rest of the code
can still reference these classes without importing bittensor itself.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# ── Bittensor-conditional base class ────────────────────────────────────────

try:
    import bittensor as bt

    _SynapseBase = bt.Synapse
except ImportError:
    # Lightweight shim for local / CI environments without bittensor
    class _SynapseBase:  # type: ignore[no-redef]
        """Minimal Synapse stub for local mode (no bittensor installed)."""

        class dendrite:  # noqa: N801
            hotkey: str = ""

        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
            if not hasattr(self, "dendrite"):
                self.dendrite = _SynapseBase.dendrite()


# ── Exploit Submission Synapse ──────────────────────────────────────────────

class ExploitSubmissionSynapse(_SynapseBase):
    """
    Miner → Validator: submit an exploit for a specific task.

    Required fields (set by miner before sending):
      - task_id:          bytes32 hex task identifier
      - exploit_source:   raw Solidity source of the exploit

    Optional fields:
      - commit_hash:      commit-reveal hash (if commit phase was used)
      - nonce:            commit-reveal nonce (for reveal phase)

    Response fields (set by validator in forward_fn):
      - result:           dict with validation outcome
    """

    # --- Miner-set request fields ---
    task_id: str = ""
    exploit_source: str = ""
    commit_hash: str = ""
    nonce: str = ""

    # --- Validator-set response fields ---
    result: Optional[Dict[str, Any]] = None


# ── Exploit Query Synapse ───────────────────────────────────────────────────

class ExploitQuerySynapse(_SynapseBase):
    """
    Validator → Miner: query for status, prepared exploits, or heartbeats.

    Request fields (set by validator):
      - query_type:  "status" | "submit" | "heartbeat"
      - task_id:     (optional) which task to query about

    Response fields (set by miner in forward_fn):
      - response:    dict with miner's response
    """

    # --- Validator-set request fields ---
    query_type: str = "status"
    task_id: str = ""

    # --- Miner-set response fields ---
    response: Optional[Dict[str, Any]] = None
