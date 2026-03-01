// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title CommitReveal — Prevents exploit theft via commit-reveal scheme.
/// @notice Miners commit exploit hashes before revealing. Earliest valid commitment wins priority.
/// @dev Commitments are per-task. Reveal window is enforced. No gray zones.
contract CommitReveal {
    // ── Structs ──────────────────────────────────────────────────────────

    struct Commitment {
        address miner;
        bytes32 commitHash; // keccak(taskId || exploitArtifactHash || nonce)
        uint256 committedAt; // Block timestamp
        bool revealed;
        bytes32 exploitArtifactHash; // Filled on reveal
        uint256 revealedAt;
    }

    // ── Constants ────────────────────────────────────────────────────────

    uint256 public constant COMMIT_WINDOW = 2 hours;
    uint256 public constant REVEAL_WINDOW = 4 hours;
    uint256 public constant MAX_COMMITS_PER_TASK = 256;

    // ── State ────────────────────────────────────────────────────────────

    address public owner;

    // taskId => commitment index => Commitment
    mapping(bytes32 => mapping(uint256 => Commitment)) public commitments;
    // taskId => number of commitments
    mapping(bytes32 => uint256) public commitCount;
    // taskId => miner => commitment index (for lookup)
    mapping(bytes32 => mapping(address => uint256)) public minerCommitIndex;
    // taskId => miner => has committed
    mapping(bytes32 => mapping(address => bool)) public hasCommitted;
    // taskId => open timestamp (when commit window opened)
    mapping(bytes32 => uint256) public taskOpenTime;
    // taskId => is task open for commits
    mapping(bytes32 => bool) public taskOpen;

    // ── Events ───────────────────────────────────────────────────────────

    event TaskOpened(bytes32 indexed taskId, uint256 openTime);
    event CommitSubmitted(
        bytes32 indexed taskId,
        address indexed miner,
        uint256 index,
        uint256 timestamp
    );
    event ExploitRevealed(
        bytes32 indexed taskId,
        address indexed miner,
        bytes32 exploitArtifactHash,
        uint256 timestamp
    );

    // ── Errors ───────────────────────────────────────────────────────────

    error Unauthorized();
    error TaskNotOpen();
    error TaskAlreadyOpen();
    error CommitWindowClosed();
    error RevealWindowClosed();
    error RevealWindowNotOpen();
    error AlreadyCommitted();
    error AlreadyRevealed();
    error InvalidReveal();
    error MaxCommitsReached();
    error NoCommitment();
    error ZeroAddress();
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    // ── Modifiers ────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ── Task Management ──────────────────────────────────────────────────

    /// @notice Open a task for commit submissions.
    function openTask(bytes32 taskId) external onlyOwner {
        if (taskOpen[taskId]) revert TaskAlreadyOpen();
        taskOpen[taskId] = true;
        taskOpenTime[taskId] = block.timestamp;
        emit TaskOpened(taskId, block.timestamp);
    }

    // ── Commit Phase ─────────────────────────────────────────────────────

    /// @notice Submit a commitment hash. H = keccak(taskId || exploitArtifactHash || nonce)
    /// @param taskId The task being targeted.
    /// @param commitHash The blinded commitment hash.
    function commit(bytes32 taskId, bytes32 commitHash) external {
        if (!taskOpen[taskId]) revert TaskNotOpen();
        if (block.timestamp > taskOpenTime[taskId] + COMMIT_WINDOW)
            revert CommitWindowClosed();
        if (hasCommitted[taskId][msg.sender]) revert AlreadyCommitted();

        uint256 idx = commitCount[taskId];
        if (idx >= MAX_COMMITS_PER_TASK) revert MaxCommitsReached();

        commitments[taskId][idx] = Commitment({
            miner: msg.sender,
            commitHash: commitHash,
            committedAt: block.timestamp,
            revealed: false,
            exploitArtifactHash: bytes32(0),
            revealedAt: 0
        });

        minerCommitIndex[taskId][msg.sender] = idx;
        hasCommitted[taskId][msg.sender] = true;
        commitCount[taskId] = idx + 1;

        emit CommitSubmitted(taskId, msg.sender, idx, block.timestamp);
    }

    // ── Reveal Phase ─────────────────────────────────────────────────────

    /// @notice Reveal the exploit artifact hash and nonce. Must match prior commitment.
    /// @param taskId The task.
    /// @param exploitArtifactHash keccak256 of the full exploit artifact.
    /// @param nonce The blinding nonce used during commit.
    function reveal(
        bytes32 taskId,
        bytes32 exploitArtifactHash,
        bytes32 nonce
    ) external {
        if (!hasCommitted[taskId][msg.sender]) revert NoCommitment();

        uint256 openTime = taskOpenTime[taskId];
        if (block.timestamp < openTime + COMMIT_WINDOW)
            revert RevealWindowNotOpen();
        if (block.timestamp > openTime + COMMIT_WINDOW + REVEAL_WINDOW)
            revert RevealWindowClosed();

        uint256 idx = minerCommitIndex[taskId][msg.sender];
        Commitment storage c = commitments[taskId][idx];

        if (c.revealed) revert AlreadyRevealed();

        // Verify commitment
        bytes32 expected = keccak256(
            abi.encodePacked(taskId, exploitArtifactHash, nonce)
        );
        if (expected != c.commitHash) revert InvalidReveal();

        c.revealed = true;
        c.exploitArtifactHash = exploitArtifactHash;
        c.revealedAt = block.timestamp;

        emit ExploitRevealed(
            taskId,
            msg.sender,
            exploitArtifactHash,
            block.timestamp
        );
    }

    // ── View Functions ───────────────────────────────────────────────────

    /// @notice Get the earliest revealed commitment for a task that matches a given artifact hash.
    function getEarliestReveal(
        bytes32 taskId,
        bytes32 exploitArtifactHash
    ) external view returns (address miner, uint256 committedAt) {
        uint256 count = commitCount[taskId];
        uint256 earliest = type(uint256).max;
        address earliestMiner;

        for (uint256 i = 0; i < count; i++) {
            Commitment storage c = commitments[taskId][i];
            if (
                c.revealed &&
                c.exploitArtifactHash == exploitArtifactHash &&
                c.committedAt < earliest
            ) {
                earliest = c.committedAt;
                earliestMiner = c.miner;
            }
        }

        return (earliestMiner, earliest);
    }

    /// @notice Check if reveal window is currently open for a task.
    function isRevealWindowOpen(bytes32 taskId) external view returns (bool) {
        uint256 openTime = taskOpenTime[taskId];
        return
            block.timestamp >= openTime + COMMIT_WINDOW &&
            block.timestamp <= openTime + COMMIT_WINDOW + REVEAL_WINDOW;
    }

    /// @notice Check if commit window is currently open for a task.
    function isCommitWindowOpen(bytes32 taskId) external view returns (bool) {
        return
            taskOpen[taskId] &&
            block.timestamp <= taskOpenTime[taskId] + COMMIT_WINDOW;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }
}
