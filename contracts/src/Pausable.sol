// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Ownable2Step.sol";

/// @title Pausable — Emergency pause for critical contract functions.
/// @notice Owner can pause/unpause. Paused state blocks functions with `whenNotPaused`.
/// @dev Inherit from this contract and apply `whenNotPaused` to functions that
///      should be disabled during an emergency.  Only the owner (from Ownable2Step)
///      may toggle the paused state.
abstract contract Pausable is Ownable2Step {
    bool public paused;

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    error ContractPaused();
    error ContractNotPaused();

    /// @dev Reverts with `ContractPaused` if the contract is paused.
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @dev Pause the contract. Reverts if already paused.
    function pause() external onlyOwner {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @dev Unpause the contract. Reverts if not paused.
    function unpause() external onlyOwner {
        if (!paused) revert ContractNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }
}
