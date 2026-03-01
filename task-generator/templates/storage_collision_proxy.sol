// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title StorageCollisionProxy — Storage collision via naive proxy pattern.
/// @dev Vulnerable: Implementation and proxy share storage slot 0 for different variables.
contract StorageCollisionProxy {
    // Slot 0: implementation address in proxy
    address public implementation;
    // Slot 1: admin
    address public admin;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    function upgrade(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}

/// @title StorageCollisionImpl — Implementation that overwrites proxy's slot 0.
/// @dev VULNERABILITY: `owner` occupies slot 0, same as proxy's `implementation`.
contract StorageCollisionImpl {
    // Slot 0 in implementation context = slot 0 in proxy = `implementation` address
    address public owner;

    function initialize() external {
        owner = msg.sender; // Overwrites proxy.implementation!
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "Failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
