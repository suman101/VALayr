// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AuthBypassTxOrigin — tx.origin authentication bypass.
/// @dev Vulnerable: uses tx.origin instead of msg.sender for auth.
contract AuthBypassTxOrigin {
    address public owner;
    mapping(address => uint256) public allowances;

    constructor() payable {
        owner = msg.sender;
    }

    /// @dev VULNERABILITY: tx.origin can be manipulated via phishing contract.
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "Not owner");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
