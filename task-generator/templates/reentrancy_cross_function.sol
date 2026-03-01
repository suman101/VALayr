// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ReentrancyCrossFunction — Cross-function reentrancy vulnerability.
/// @dev Vulnerable: shared state between withdraw and transfer, external call before update.
contract ReentrancyCrossFunction {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Transfer balance to another address.
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    /// @notice Withdraw ETH.
    /// @dev VULNERABILITY: External call before state update; attacker can call transfer() during callback.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
