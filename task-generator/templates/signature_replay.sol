// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SignatureReplay — ECDSA signature replay vulnerability.
/// @dev Vulnerable: signed message does not include a nonce or chain ID,
///      allowing the same signature to be replayed multiple times or
///      across chains.
contract SignatureReplay {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() payable {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev VULNERABILITY: No nonce tracking — the same (to, amount, v, r, s)
    ///      can be submitted repeatedly to drain the contract.
    ///      Also missing chain ID in the signed hash, enabling cross-chain replay.
    function withdrawWithSig(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address signer = ecrecover(ethSignedHash, v, r, s);
        require(signer == owner, "Invalid signature");
        require(address(this).balance >= amount, "Insufficient funds");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
