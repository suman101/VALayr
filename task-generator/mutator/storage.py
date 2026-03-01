"""Storage layout mutator — shifts slot layout to defeat bytecode fingerprints."""

import hashlib

from task_generator.mutator.base import Mutator


class StorageLayoutMutator(Mutator):
    """
    Insert a private padding variable right after the first ``{`` in the
    contract body, shifting all subsequent storage slots by one.

    Parameters (``params``)
    -----------------------
    storage_prefix : str
        Unique prefix used to name the padding variable and derive its
        initial value deterministically.
    """

    name = "storage_layout"

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        prefix: str = params.get("storage_prefix", "")
        if not prefix:
            return source

        # Deterministic padding value from prefix (hashlib, not builtin hash
        # which varies across processes unless PYTHONHASHSEED=0)
        pad_value = int(hashlib.sha256(prefix.encode()).hexdigest()[:16], 16)
        packer = f"\n    uint256 private _pad_{prefix} = {pad_value};\n"

        # Insert after first opening brace of the contract body
        idx = source.find("{")
        if idx > 0:
            source = source[: idx + 1] + packer + source[idx + 1 :]
        return source
