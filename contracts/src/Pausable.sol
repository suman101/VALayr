// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Ownable2Step.sol";

/// @title Pausable — Emergency pause for critical contract functions.
/// @notice Owner can pause/unpause. Paused state blocks functions with `whenNotPaused`.
abstract contract Pausable is Ownable2Step {
    bool public paused;

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    error ContractPaused();
    error ContractNotPaused();

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    function pause() external onlyOwner {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        if (!paused) revert ContractNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }
}
