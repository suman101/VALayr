// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AuthBypassMissingModifier — Missing access control on critical function.
/// @dev Vulnerable: setOwner has no access restriction.
contract AuthBypassMissingModifier {
    address public owner;
    uint256 public treasuryBalance;

    constructor() payable {
        owner = msg.sender;
        treasuryBalance = msg.value;
    }

    /// @dev VULNERABILITY: No modifier — anyone can call.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function withdrawTreasury() external {
        require(msg.sender == owner, "Not owner");
        uint256 amount = address(this).balance;
        treasuryBalance = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
