"""Dead-code injection mutator — adds inert functions / state variables."""

import random as _random

from task_generator.mutator.base import Mutator

# Pool of harmless Solidity snippets that compile but do nothing meaningful.
_DEAD_FUNCTIONS = [
    "    function _noop{idx}() internal pure returns (uint256) {{ return {val}; }}",
    "    function _check{idx}(address a) internal pure {{ require(a != address(0)); }}",
    "    function _hash{idx}(bytes memory d) internal pure returns (bytes32) {{ return keccak256(d); }}",
]

_DEAD_VARIABLES = [
    "    uint256 private constant _SENTINEL{idx} = {val};",
    "    address private _placeholder{idx};",
    "    bool private _flag{idx};",
]


class DeadCodeMutator(Mutator):
    """
    Inject deterministic dead-code snippets to change source hash
    without altering exploitable semantics.

    TG-3/TG-7 fix: injected identifiers use a ``__dc_`` prefix that is
    unlikely to shadow contract state variables.

    Parameters (``params``)
    -----------------------
    dead_code_count : int
        Number of dead snippets to inject (default: 2).
    """

    name = "deadcode"

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        count: int = params.get("dead_code_count", 2)
        if count <= 0:
            return source

        rng = _random.Random(seed)
        snippets: list[str] = []

        for i in range(count):
            val = rng.randint(1, 2**64)
            # TG-7 fix: use __dc_ prefix to avoid shadowing contract variables
            idx_tag = f"__dc_{seed}_{i}"
            pool = _DEAD_FUNCTIONS if rng.random() > 0.5 else _DEAD_VARIABLES
            template = rng.choice(pool)
            snippets.append(template.format(idx=idx_tag, val=val))

        block = "\n".join(snippets) + "\n"

        # Insert before the last closing brace (end of contract body)
        last_brace = source.rfind("}")
        if last_brace > 0:
            source = source[:last_brace] + "\n" + block + source[last_brace:]
        return source
