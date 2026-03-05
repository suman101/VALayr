// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Create2Frontrun — CREATE2 deployment address frontrunning.
/// @dev Vulnerable: anyone can call deploy() with the same salt to
///      front-run the intended deployment, seizing ownership of the
///      known deterministic address.
contract Create2Frontrun {
    address public owner;
    address public lastDeployed;

    event Deployed(address addr, address deployer, bytes32 salt);

    constructor() {
        owner = msg.sender;
    }

    /// @dev VULNERABILITY: deploy() is external without access control.
    ///      Since CREATE2 addresses are deterministic, an attacker watching
    ///      the mempool can front-run the deploy tx with the same salt,
    ///      causing the original tx to revert (address already taken)
    ///      and the attacker to control the deployed contract.
    function deploy(bytes32 salt) external returns (address) {
        // Simple wallet bytecode: stores msg.sender (the factory caller's
        // context) as owner in the deployed contract's storage.
        bytes memory bytecode = abi.encodePacked(
            type(SimpleWallet).creationCode,
            abi.encode(msg.sender)
        );
        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Deploy failed");
        lastDeployed = addr;
        emit Deployed(addr, msg.sender, salt);
        return addr;
    }

    /// @notice Compute the deterministic address for a given salt and deployer.
    function computeAddress(
        bytes32 salt,
        address deployer
    ) external view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(SimpleWallet).creationCode,
            abi.encode(deployer)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }
}

/// @dev Minimal wallet that is deployed by the factory.
contract SimpleWallet {
    address public walletOwner;

    constructor(address _owner) payable {
        walletOwner = _owner;
    }

    function withdraw() external {
        require(msg.sender == walletOwner, "Not owner");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "Failed");
    }

    receive() external payable {}
}
