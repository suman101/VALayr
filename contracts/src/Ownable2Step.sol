// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Ownable2Step — Two-step ownership transfer with optional timelock.
/// @notice Prevents accidental ownership loss by requiring the new owner to
///         explicitly accept. Optional `TRANSFER_DELAY` adds a timelock for
///         production deployments.
/// @dev Inherit this instead of raw `owner` patterns. All subnet contracts
///      (ExploitRegistry, ProtocolRegistry, InvariantRegistry,
///      AdversarialScoring) should use this as their ownership primitive.
abstract contract Ownable2Step {
    address public owner;
    address public pendingOwner;
    uint256 public ownershipTransferTimestamp;

    /// @dev Override in production subclass for a non-zero delay (e.g., 48 hours).
    uint256 public constant TRANSFER_DELAY = 0;

    event OwnershipTransferStarted(
        address indexed previousOwner,
        address indexed newOwner
    );
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    event OwnershipTransferCancelled(address indexed cancelledOwner);

    error Unauthorized();
    error ZeroAddress();
    error TransferNotReady();
    error NoPendingTransfer();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Initiate ownership transfer. New owner must call `acceptOwnership()`.
    function transferOwnership(address newOwner) external virtual onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        ownershipTransferTimestamp = block.timestamp;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accept pending ownership transfer.
    function acceptOwnership() external virtual {
        if (msg.sender != pendingOwner) revert Unauthorized();
        if (block.timestamp < ownershipTransferTimestamp + TRANSFER_DELAY) {
            revert TransferNotReady();
        }

        address prev = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        ownershipTransferTimestamp = 0;

        emit OwnershipTransferred(prev, owner);
    }

    /// @notice Cancel a pending ownership transfer.
    function cancelOwnershipTransfer() external virtual onlyOwner {
        if (pendingOwner == address(0)) revert NoPendingTransfer();
        address cancelled = pendingOwner;
        pendingOwner = address(0);
        ownershipTransferTimestamp = 0;
        emit OwnershipTransferCancelled(cancelled);
    }
}
