"""
Pluggable mutation framework for deterministic task diversification.

Mutators transform Solidity source code to produce structurally
different but functionally equivalent vulnerable contracts.  This
defeats fingerprint-only approaches and forces miners to understand
the actual vulnerability rather than pattern-matching bytecodes.

Usage:
    from task_generator.mutator import MutationRegistry

    registry = MutationRegistry(seed=42)
    mutated_source = registry.apply(source, mutations_dict)
"""

from task_generator.mutator.base import Mutator
from task_generator.mutator.registry import MutationRegistry
from task_generator.mutator.rename import RenameMutator
from task_generator.mutator.storage import StorageLayoutMutator
from task_generator.mutator.balance import BalanceMutator
from task_generator.mutator.deadcode import DeadCodeMutator

__all__ = [
    "Mutator",
    "MutationRegistry",
    "RenameMutator",
    "StorageLayoutMutator",
    "BalanceMutator",
    "DeadCodeMutator",
]
