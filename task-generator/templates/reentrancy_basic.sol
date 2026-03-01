// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ReentrancyBasic — Classic reentrancy vulnerability.
/// @dev Vulnerable: sends ETH before updating balance.
contract ReentrancyBasic {
    mapping(address => uint256) public balances;

    /// @notice Deposit ETH into the contract.
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw all deposited ETH.
    /// @dev VULNERABILITY: External call before state update.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // BUG: sends before zeroing balance
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] = 0;
    }

    /// @notice Get contract balance.
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
