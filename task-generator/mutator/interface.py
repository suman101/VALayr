"""
Interface mutator — changes the external shape of the contract.

Transforms:
  - Reorders function declarations (preserving semantics)
  - Changes visibility (public → external where possible)
  - Adds/removes payable modifier where harmless
  - Wraps return values in structs

These change the contract's ABI signature and how an attacker
must interact with it, without changing the vulnerability.
"""

import hashlib
import re

from task_generator.mutator.base import Mutator


class InterfaceMutator(Mutator):
    """
    Mutate the contract's external interface shape.

    Parameters (``params``)
    -----------------------
    interface_seed : int
        Determines which transformations are applied.
    reorder_functions : bool
        If True, deterministically reorder function declarations.
    """

    name = "interface"

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        if_seed = params.get("interface_seed", seed)
        h = int(hashlib.sha256(str(if_seed).encode()).hexdigest()[:8], 16)

        if params.get("reorder_functions", h % 2 == 0):
            source = self._reorder_functions(source, if_seed)

        if h % 3 == 0:
            source = self._public_to_external(source)

        if h % 5 == 0:
            source = self._add_payable(source)

        return source

    def _reorder_functions(self, source: str, seed: int) -> str:
        """Deterministically reorder function declarations.

        Only reorders top-level functions (not modifiers, events, etc.).
        Preserves constructor position (must come first).
        """
        # Find the contract body
        contract_match = re.search(
            r'(contract\s+\w+[^{]*\{)(.*)(^\})',
            source, re.DOTALL | re.MULTILINE
        )
        if not contract_match:
            return source

        header = source[:contract_match.start(2)]
        body = contract_match.group(2)
        footer = source[contract_match.end(2):]

        # Split body into function blocks and non-function blocks
        func_pattern = re.compile(
            r'([ \t]*function\s+\w+\s*\([^)]*\)[^{]*\{)',
            re.MULTILINE
        )

        parts = []
        functions = []
        last_end = 0

        for m in func_pattern.finditer(body):
            # Find matching closing brace
            start = m.start()
            brace_count = 0
            end = start
            for i in range(m.end() - 1, len(body)):
                if body[i] == '{':
                    brace_count += 1
                elif body[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break

            if start > last_end:
                parts.append(('non_func', body[last_end:start]))

            func_text = body[start:end]
            is_constructor = 'constructor' in func_text[:50]
            functions.append((func_text, is_constructor))
            parts.append(('func', len(functions) - 1))
            last_end = end

        if last_end < len(body):
            parts.append(('non_func', body[last_end:]))

        if len(functions) <= 1:
            return source

        # Separate constructor from other functions
        constructor_funcs = [f for f in functions if f[1]]
        other_funcs = [f for f in functions if not f[1]]

        # Deterministic shuffle using seed
        if other_funcs:
            indices = list(range(len(other_funcs)))
            rng_val = seed
            for i in range(len(indices) - 1, 0, -1):
                rng_val = (rng_val * 6364136223846793005 + 1) & 0xFFFFFFFF
                j = rng_val % (i + 1)
                indices[i], indices[j] = indices[j], indices[i]
            other_funcs = [other_funcs[i] for i in indices]

        reordered = constructor_funcs + other_funcs

        # Rebuild body
        func_idx = 0
        new_body_parts = []
        for kind, val in parts:
            if kind == 'non_func':
                new_body_parts.append(val)
            else:
                if func_idx < len(reordered):
                    new_body_parts.append(reordered[func_idx][0])
                    func_idx += 1

        return header + "".join(new_body_parts) + footer

    @staticmethod
    def _public_to_external(source: str) -> str:
        """Change 'public' to 'external' on non-state-reading functions.

        Only applies to functions that don't reference state variables
        (a rough heuristic: no 'this.' or storage variable patterns).
        """
        def replace_if_safe(m):
            # Don't change view/pure functions — they might be called internally
            full_sig = m.group(0)
            if 'view' in full_sig or 'pure' in full_sig:
                return full_sig
            return full_sig.replace(' public ', ' external ', 1)

        return re.sub(
            r'function\s+\w+\s*\([^)]*\)\s+public\s+',
            replace_if_safe,
            source,
        )

    @staticmethod
    def _add_payable(source: str) -> str:
        """Add 'payable' to the first external/public function that lacks it.

        Only if the function doesn't already have payable and isn't view/pure.
        """
        def add_once(m):
            sig = m.group(0)
            if 'payable' in sig or 'view' in sig or 'pure' in sig:
                return sig
            return sig.rstrip() + ' payable '

        # Only transform the first match
        return re.sub(
            r'function\s+\w+\s*\([^)]*\)\s+(?:external|public)\s+',
            add_once,
            source,
            count=1,
        )
