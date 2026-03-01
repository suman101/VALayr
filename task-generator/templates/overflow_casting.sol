// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title OverflowCasting — Unsafe downcasting vulnerability.
/// @dev Vulnerable: casting uint256 to uint8 silently truncates.
contract OverflowCasting {
    mapping(address => uint8) public balances; // BUG: uint8 max = 255
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    /// @dev VULNERABILITY: uint256 amount silently truncated to uint8.
    function deposit() external payable {
        // BUG: Depositing 256 wei wraps to 0, 257 wraps to 1, etc.
        balances[msg.sender] = uint8(msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
