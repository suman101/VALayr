"""Rename mutator — deterministic variable / function renaming."""

import re

from task_generator.mutator.base import Mutator


class RenameMutator(Mutator):
    """
    Replace identifiers according to a provided mapping.

    Parameters (``params``)
    -----------------------
    rename_map : dict[str, str]
        ``{old_name: new_name}`` pairs applied via literal string replace.
    """

    name = "rename"

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        rename_map: dict[str, str] = params.get("rename_map", {})
        for old_name, new_name in rename_map.items():
            source = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, source)
        return source
