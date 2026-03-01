// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AuthBypassInitializer — Unprotected initializer function.
/// @dev Vulnerable: initialize() can be called by anyone, including after deployment.
contract AuthBypassInitializer {
    address public owner;
    bool public initialized;
    uint256 public treasuryBalance;

    /// @dev VULNERABILITY: No protection against re-initialization or unauthorized init.
    function initialize() external payable {
        // BUG: Missing `require(!initialized)` or initializer guard
        owner = msg.sender;
        treasuryBalance = msg.value;
        initialized = true;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        require(amount <= address(this).balance, "Insufficient");
        treasuryBalance -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
