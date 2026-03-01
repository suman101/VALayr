// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title StorageCollisionDelegatecall — Delegatecall storage collision.
/// @dev Vulnerable: Library-style delegatecall with mismatched storage layout.
contract StorageCollisionDelegatecall {
    address public owner;
    address public lib;
    uint256 public storedValue;

    constructor(address _lib) {
        owner = msg.sender;
        lib = _lib;
    }

    function setValueViaLib(uint256 _val) external {
        // BUG: delegatecall to lib writes to THIS contract's storage
        (bool ok, ) = lib.delegatecall(
            abi.encodeWithSignature("setValue(uint256)", _val)
        );
        require(ok, "Delegatecall failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

/// @title MaliciousLib — Library with different storage layout.
/// @dev setValue writes to slot 0 (owner in caller context).
contract MaliciousLib {
    // Slot 0 here maps to slot 0 in caller = `owner`
    uint256 public storedValue;

    function setValue(uint256 _val) external {
        storedValue = _val; // Overwrites `owner` in caller
    }
}
