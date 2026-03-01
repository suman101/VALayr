"""Balance literal mutator — rewrites the first ether/wei literal."""

import re

from task_generator.mutator.base import Mutator


class BalanceMutator(Mutator):
    """
    Replace the first numeric literal adjacent to ``ether`` or ``wei``
    with the value supplied in ``params["initial_balance_literal"]``.

    Parameters (``params``)
    -----------------------
    initial_balance_literal : str | int
        The replacement numeric literal.
    """

    name = "balance"

    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        literal = params.get("initial_balance_literal")
        if literal is None:
            return source

        source = re.sub(
            r"(\d+)\s*(ether|wei)",
            rf"{literal} \2",
            source,
            count=1,
        )
        return source
