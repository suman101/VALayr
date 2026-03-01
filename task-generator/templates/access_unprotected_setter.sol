// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AccessUnprotectedSetter — Unprotected state setter.
/// @dev Vulnerable: critical state variables settable by anyone.
contract AccessUnprotectedSetter {
    address public owner;
    address public withdrawalAddress;
    uint256 public withdrawalLimit;

    constructor() payable {
        owner = msg.sender;
        withdrawalAddress = msg.sender;
        withdrawalLimit = 1 ether;
    }

    /// @dev VULNERABILITY: Anyone can change the withdrawal address.
    function setWithdrawalAddress(address _addr) external {
        withdrawalAddress = _addr;
    }

    /// @dev VULNERABILITY: Anyone can change the withdrawal limit.
    function setWithdrawalLimit(uint256 _limit) external {
        withdrawalLimit = _limit;
    }

    function withdraw() external {
        require(msg.sender == withdrawalAddress, "Not authorized");
        uint256 amount = address(this).balance;
        if (amount > withdrawalLimit) amount = withdrawalLimit;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
