// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/CommitReveal.sol";

/// @title CommitRevealTest — Foundry tests for the Commit-Reveal mechanism.
contract CommitRevealTest is Test {
    CommitReveal public cr;

    bytes32 constant TASK_ID = keccak256("task-001");
    bytes32 constant ARTIFACT_HASH = keccak256("exploit-artifact");
    bytes32 constant NONCE = keccak256("secret-nonce");

    function setUp() public {
        cr = new CommitReveal();
    }

    function test_openTask() public {
        cr.openTask(TASK_ID);
        assert(cr.taskOpen(TASK_ID));
        assert(cr.isCommitWindowOpen(TASK_ID));
    }

    function test_commit() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        assert(cr.hasCommitted(TASK_ID, address(this)));
        assert(cr.commitCount(TASK_ID) == 1);
    }

    function test_doubleCommit_reverts() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        try cr.commit(TASK_ID, commitHash) {
            revert("Should have reverted on double commit");
        } catch {}
    }

    function test_commitWithoutTask_reverts() public {
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        try cr.commit(TASK_ID, commitHash) {
            revert("Should have reverted on unopened task");
        } catch {}
    }

    // ── Reveal tests (require vm.warp) ──────────────────────────────────

    function test_revealAfterCommitWindow() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        // Warp past COMMIT_WINDOW (2 hours) into REVEAL_WINDOW
        vm.warp(block.timestamp + 2 hours + 1);

        cr.reveal(TASK_ID, ARTIFACT_HASH, NONCE);
        assert(cr.isRevealWindowOpen(TASK_ID));
    }

    function test_revealBeforeCommitWindowEnds_reverts() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        // Still within COMMIT_WINDOW — reveal should revert
        vm.expectRevert(CommitReveal.RevealWindowNotOpen.selector);
        cr.reveal(TASK_ID, ARTIFACT_HASH, NONCE);
    }

    function test_revealAfterRevealWindowCloses_reverts() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        // Warp past COMMIT_WINDOW + REVEAL_WINDOW (2h + 4h + 1s)
        vm.warp(block.timestamp + 6 hours + 1);

        vm.expectRevert(CommitReveal.RevealWindowClosed.selector);
        cr.reveal(TASK_ID, ARTIFACT_HASH, NONCE);
    }

    function test_revealWithWrongNonce_reverts() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        vm.warp(block.timestamp + 2 hours + 1);

        vm.expectRevert(CommitReveal.InvalidReveal.selector);
        cr.reveal(TASK_ID, ARTIFACT_HASH, keccak256("wrong-nonce"));
    }

    function test_doubleReveal_reverts() public {
        cr.openTask(TASK_ID);
        bytes32 commitHash = keccak256(
            abi.encodePacked(TASK_ID, ARTIFACT_HASH, NONCE)
        );
        cr.commit(TASK_ID, commitHash);

        vm.warp(block.timestamp + 2 hours + 1);
        cr.reveal(TASK_ID, ARTIFACT_HASH, NONCE);

        vm.expectRevert(CommitReveal.AlreadyRevealed.selector);
        cr.reveal(TASK_ID, ARTIFACT_HASH, NONCE);
    }
}
