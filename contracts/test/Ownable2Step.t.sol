// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/Ownable2Step.sol";

/// @dev Concrete implementation for testing the abstract Ownable2Step.
contract OwnableTestHarness is Ownable2Step {
    constructor() Ownable2Step(0) {}
}

/// @title Ownable2StepTest — Foundry tests for the Ownable2Step base contract.
contract Ownable2StepTest is Test {
    OwnableTestHarness public owned;
    address newOwner = address(0x42);
    address nobody = address(0xDEAD);

    function setUp() public {
        owned = new OwnableTestHarness();
    }

    // ── Basic ownership ──────────────────────────────────────────────────

    function test_owner_is_deployer() public view {
        assertEq(owned.owner(), address(this));
    }

    function test_pendingOwner_initially_zero() public view {
        assertEq(owned.pendingOwner(), address(0));
    }

    // ── transferOwnership ────────────────────────────────────────────────

    function test_transferOwnership_sets_pending() public {
        owned.transferOwnership(newOwner);
        assertEq(owned.pendingOwner(), newOwner);
        // Owner not changed yet
        assertEq(owned.owner(), address(this));
    }

    function test_transferOwnership_zeroAddress_reverts() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        owned.transferOwnership(address(0));
    }

    function test_transferOwnership_nonOwner_reverts() public {
        vm.prank(nobody);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.transferOwnership(newOwner);
    }

    function test_transferOwnership_emits_event() public {
        vm.expectEmit(true, true, false, false);
        emit Ownable2Step.OwnershipTransferStarted(address(this), newOwner);
        owned.transferOwnership(newOwner);
    }

    // ── acceptOwnership ──────────────────────────────────────────────────

    function test_acceptOwnership_transfers() public {
        owned.transferOwnership(newOwner);
        vm.prank(newOwner);
        owned.acceptOwnership();
        assertEq(owned.owner(), newOwner);
        assertEq(owned.pendingOwner(), address(0));
    }

    function test_acceptOwnership_nonPending_reverts() public {
        owned.transferOwnership(newOwner);
        vm.prank(nobody);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.acceptOwnership();
    }

    function test_acceptOwnership_emits_event() public {
        owned.transferOwnership(newOwner);
        vm.prank(newOwner);
        vm.expectEmit(true, true, false, false);
        emit Ownable2Step.OwnershipTransferred(address(this), newOwner);
        owned.acceptOwnership();
    }

    function test_acceptOwnership_clears_timestamp() public {
        owned.transferOwnership(newOwner);
        assertTrue(owned.ownershipTransferTimestamp() > 0);
        vm.prank(newOwner);
        owned.acceptOwnership();
        assertEq(owned.ownershipTransferTimestamp(), 0);
    }

    // ── cancelOwnershipTransfer ──────────────────────────────────────────

    function test_cancelOwnershipTransfer() public {
        owned.transferOwnership(newOwner);
        owned.cancelOwnershipTransfer();
        assertEq(owned.pendingOwner(), address(0));
        assertEq(owned.ownershipTransferTimestamp(), 0);
    }

    function test_cancelOwnershipTransfer_nonOwner_reverts() public {
        owned.transferOwnership(newOwner);
        vm.prank(nobody);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.cancelOwnershipTransfer();
    }

    function test_cancelOwnershipTransfer_noPending_reverts() public {
        vm.expectRevert(Ownable2Step.NoPendingTransfer.selector);
        owned.cancelOwnershipTransfer();
    }

    function test_cancelOwnershipTransfer_emits_event() public {
        owned.transferOwnership(newOwner);
        vm.expectEmit(true, false, false, false);
        emit Ownable2Step.OwnershipTransferCancelled(newOwner);
        owned.cancelOwnershipTransfer();
    }

    // ── Overwrite pending ────────────────────────────────────────────────

    function test_transferOwnership_overwrite_pending() public {
        address second = address(0x99);
        owned.transferOwnership(newOwner);
        owned.transferOwnership(second);
        assertEq(owned.pendingOwner(), second);

        // Original pending can no longer accept
        vm.prank(newOwner);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.acceptOwnership();

        // New pending can accept
        vm.prank(second);
        owned.acceptOwnership();
        assertEq(owned.owner(), second);
    }

    // ── Double accept ────────────────────────────────────────────────────

    function test_acceptOwnership_twice_reverts() public {
        owned.transferOwnership(newOwner);
        vm.prank(newOwner);
        owned.acceptOwnership();

        // Second accept with no pending should revert
        vm.prank(newOwner);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.acceptOwnership();
    }

    // ── New owner can transfer again ─────────────────────────────────────

    function test_new_owner_can_initiate_transfer() public {
        owned.transferOwnership(newOwner);
        vm.prank(newOwner);
        owned.acceptOwnership();

        // Old owner cannot transfer
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        owned.transferOwnership(nobody);

        // New owner can
        vm.prank(newOwner);
        owned.transferOwnership(nobody);
        assertEq(owned.pendingOwner(), nobody);
    }
}
