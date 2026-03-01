// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title OverflowUnchecked — Integer overflow in unchecked block.
/// @dev Vulnerable: arithmetic in unchecked block allows underflow/overflow.
contract OverflowUnchecked {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() payable {
        balances[msg.sender] = msg.value;
        totalSupply = msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    /// @dev VULNERABILITY: Unchecked arithmetic allows underflow.
    function transfer(address to, uint256 amount) external {
        unchecked {
            // BUG: If amount > balances[msg.sender], this underflows to huge number
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
