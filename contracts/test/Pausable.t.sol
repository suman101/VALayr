// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/Pausable.sol";

/// @dev Concrete implementation for testing the abstract Pausable contract.
contract PausableHarness is Pausable {
    uint256 public counter;

    function increment() external whenNotPaused {
        counter++;
    }
}

contract PausableTest is Test {
    PausableHarness public h;

    function setUp() public {
        h = new PausableHarness();
    }

    function test_initiallyNotPaused() public view {
        assertFalse(h.paused());
    }

    function test_pause() public {
        h.pause();
        assertTrue(h.paused());
    }

    function test_pause_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit Pausable.Paused(address(this));
        h.pause();
    }

    function test_unpause() public {
        h.pause();
        h.unpause();
        assertFalse(h.paused());
    }

    function test_unpause_emits_event() public {
        h.pause();
        vm.expectEmit(true, false, false, false);
        emit Pausable.Unpaused(address(this));
        h.unpause();
    }

    function test_pause_nonOwner_reverts() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        h.pause();
    }

    function test_unpause_nonOwner_reverts() public {
        h.pause();
        vm.prank(address(0xBEEF));
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        h.unpause();
    }

    function test_doublePause_reverts() public {
        h.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        h.pause();
    }

    function test_doubleUnpause_reverts() public {
        vm.expectRevert(Pausable.ContractNotPaused.selector);
        h.unpause();
    }

    function test_whenNotPaused_allows() public {
        h.increment();
        assertEq(h.counter(), 1);
    }

    function test_whenNotPaused_blocks_when_paused() public {
        h.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        h.increment();
    }

    function test_whenNotPaused_resumes_after_unpause() public {
        h.pause();
        h.unpause();
        h.increment();
        assertEq(h.counter(), 1);
    }
}
