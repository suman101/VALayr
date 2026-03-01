// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AccessSelfdestruct — Unprotected selfdestruct.
/// @dev Vulnerable: selfdestruct callable by anyone (or via delegatecall).
contract AccessSelfdestruct {
    address public owner;
    uint256 public storedValue;

    constructor() payable {
        owner = msg.sender;
    }

    function store(uint256 val) external {
        storedValue = val;
    }

    /// @dev VULNERABILITY: No access control on destroy.
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
