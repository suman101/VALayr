"""
Control-flow mutator — restructures vulnerable logic to defeat pattern matching.

Unlike cosmetic mutators (rename, dead code), this changes HOW the
vulnerability is expressed:
  - Splits a single vulnerable function into setup + action
  - Reorders independent statements
  - Wraps guards in modifier vs. inline require
  - Extracts inline math into library calls

The vulnerability itself is preserved but its *shape* changes.
"""

import hashlib
import re

from task_generator.mutator.base import Mutator


class ControlFlowMutator(Mutator):
    """
    Restructure control flow around the vulnerability.

    Parameters (``params``)
    -----------------------
    controlflow_seed : int
        Determines which transformations are applied.
    """

    name = "controlflow"

    # Patterns for function bodies with require/if guards
    _REQUIRE_PAT = re.compile(
        r'(require\s*\(\s*)([^;]+?)(\s*\)\s*;)', re.DOTALL
    )
    _INLINE_IF_PAT = re.compile(
        r'if\s*\(\s*([^{]+?)\s*\)\s*\{?\s*revert\s*\(\s*\)\s*;?\s*\}?'
    )

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        cf_seed = params.get("controlflow_seed", seed)
        # Use hash for deterministic selection
        h = int(hashlib.sha256(str(cf_seed).encode()).hexdigest()[:8], 16)

        transforms = [
            self._extract_modifier,
            self._wrap_require_in_if,
            self._split_withdraw_pattern,
        ]

        # Apply 1-2 transforms based on seed
        n_transforms = (h % 2) + 1
        for i in range(n_transforms):
            idx = (h + i) % len(transforms)
            source = transforms[idx](source, cf_seed + i)

        return source

    def _extract_modifier(self, source: str, seed: int) -> str:
        """Convert first inline require() into a modifier.

        TG-8 fix: after extracting the require we must also attach the
        new modifier to the enclosing function's signature, otherwise the
        guard is silently dropped.
        """
        match = self._REQUIRE_PAT.search(source)
        if not match:
            return source

        condition = match.group(2).strip()
        mod_name = f"_guard_{seed % 1000}"

        modifier_code = (
            f"\n    modifier {mod_name}() {{\n"
            f"        require({condition});\n"
            f"        _;\n"
            f"    }}\n"
        )

        # Find the function signature containing this require so we can
        # attach the modifier to it.
        func_sig_pat = re.compile(
            r'(function\s+\w+\s*\([^)]*\)\s*'       # function name(args)
            r'(?:(?:public|external|internal|private)\s*)*'  # visibility
            r'(?:(?:view|pure|payable)\s*)*'          # mutability
            r'(?:(?:virtual|override)\s*)*'           # extras
            r'(?:returns\s*\([^)]*\)\s*)?)'           # returns(...)
            r'(\{)',                                   # opening brace
            re.DOTALL,
        )
        # Walk backwards from the require match to find its enclosing function
        enclosing_func = None
        for fm in func_sig_pat.finditer(source):
            if fm.start() < match.start():
                enclosing_func = fm
            else:
                break

        if enclosing_func is None:
            return source  # Can't safely extract — skip

        # Remove the require from original location
        source = source[:match.start()] + "// guard extracted" + source[match.end():]

        # Attach modifier to the function signature (before the opening brace)
        # Recompute the enclosing function match position in the modified source
        enclosing_func = None
        for fm in func_sig_pat.finditer(source):
            if fm.start() < match.start():
                enclosing_func = fm
            else:
                break

        if enclosing_func:
            brace_pos = enclosing_func.start(2)
            source = source[:brace_pos] + f" {mod_name} " + source[brace_pos:]

        # Insert modifier definition before last closing brace
        last_brace = source.rfind("}")
        if last_brace > 0:
            source = source[:last_brace] + modifier_code + source[last_brace:]

        return source

    def _wrap_require_in_if(self, source: str, seed: int) -> str:
        """Convert require(cond) to if (!cond) revert()."""
        match = self._REQUIRE_PAT.search(source)
        if not match:
            return source

        full = match.group(0)
        condition = match.group(2).strip()

        # Remove trailing string message if present: require(cond, "msg")
        # Just use the actual condition part
        if "," in condition:
            condition = condition.split(",")[0].strip()

        replacement = f"if (!({condition})) {{ revert(); }}"
        source = source.replace(full, replacement, 1)
        return source

    def _split_withdraw_pattern(self, source: str, seed: int) -> str:
        """Split a withdraw-style function into check + effect + interaction.

        Detects patterns like:
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            (bool ok, ) = msg.sender.call{value: amount}("");

        And splits into separate internal functions.
        """
        # Look for function with .call{value
        call_pattern = re.compile(
            r'(function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)[^{]*\{)'
            r'(.*?\.call\{value[^}]*\}[^;]*;.*?)\}',
            re.DOTALL
        )

        match = call_pattern.search(source)
        if not match:
            return source

        func_header = match.group(1)
        func_name = match.group(2)
        func_body = match.group(3)

        helper_name = f"_do_{func_name}_{seed % 100}"
        new_func = f"{func_header}\n        {helper_name}();\n    }}\n"
        helper = (
            f"    function {helper_name}() internal {{\n"
            f"    {func_body}\n"
            f"    }}\n"
        )

        source = source[:match.start()] + new_func + source[match.end():]

        # Insert helper before last brace
        last_brace = source.rfind("}")
        if last_brace > 0:
            source = source[:last_brace] + "\n" + helper + source[last_brace:]

        return source
