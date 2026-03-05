"""
Mutation registry — composes and chains mutators deterministically.

The registry holds a fixed, ordered list of mutators.  When ``apply``
is called with a mutations dict the registry iterates through each
registered mutator and delegates the relevant slice of the params.
"""

from __future__ import annotations

from task_generator.mutator.base import Mutator
from task_generator.mutator.rename import RenameMutator
from task_generator.mutator.storage import StorageLayoutMutator
from task_generator.mutator.balance import BalanceMutator
from task_generator.mutator.deadcode import DeadCodeMutator
from task_generator.mutator.controlflow import ControlFlowMutator
from task_generator.mutator.interface import InterfaceMutator


# Default ordered pipeline — cosmetic mutators run first, then semantic
_DEFAULT_MUTATORS: list[Mutator] = [
    RenameMutator(),
    StorageLayoutMutator(),
    BalanceMutator(),
    DeadCodeMutator(),
    ControlFlowMutator(),
    InterfaceMutator(),
]


class MutationRegistry:
    """
    Ordered collection of :class:`Mutator` instances.

    Parameters
    ----------
    mutators : list[Mutator] | None
        Custom mutator pipeline.  ``None`` uses the built-in defaults.
    seed : int
        Base seed forwarded to each mutator's ``apply``.
    """

    def __init__(self, mutators: list[Mutator] | None = None, seed: int = 0):
        self.mutators = mutators if mutators is not None else list(_DEFAULT_MUTATORS)
        self.seed = seed

    # ── Public API ─────────────────────────────────────────────────────

    def apply(self, source: str, mutations: dict) -> str:
        """
        Run *source* through every mutator in order.

        Parameters
        ----------
        source : str
            Raw Solidity code.
        mutations : dict
            Combined parameter bag — each mutator picks the keys it
            understands and ignores the rest.

        Returns
        -------
        str
            Fully mutated source.
        """
        for i, mutator in enumerate(self.mutators):
            source = mutator.apply(source, mutations, seed=self.seed + i)
        return source

    def register(self, mutator: Mutator) -> None:
        """Append a mutator to the pipeline."""
        self.mutators.append(mutator)

    def list_mutators(self) -> list[str]:
        """Return names of all registered mutators."""
        return [m.name for m in self.mutators]
