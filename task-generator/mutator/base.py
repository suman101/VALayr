"""Abstract base class for all mutators."""

from abc import ABC, abstractmethod


class Mutator(ABC):
    """
    Base class for source-level mutations.

    Every mutator MUST be:
      - Deterministic:  same (source, params, seed) → same output
      - Composable:     output of one mutator is valid input for another
      - Semantics-preserving: the resulting contract must still compile
        and exhibit the same vulnerability class
    """

    name: str = "base"

    @abstractmethod
    def apply(self, source: str, params: dict, seed: int = 0) -> str:
        """
        Apply the mutation to *source* using *params*.

        Parameters
        ----------
        source : str
            Solidity source code.
        params : dict
            Mutation-specific parameters (e.g. ``rename_map``).
        seed : int
            Deterministic seed for any randomised decisions.

        Returns
        -------
        str
            Mutated Solidity source.
        """
        ...
