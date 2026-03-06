// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Ownable2Step.sol";
import "./Pausable.sol";

/// @title Treasury — Winner-takes-all competition escrow.
/// @notice Manages timed competitions where miners compete to find exploits.
///         The best exploit (highest severity) wins the entire prize pool.
/// @dev Lifecycle: create → fund → miners submit → deadline passes → settle → winner withdraws.
contract Treasury is Ownable2Step, Pausable {
    // ── Reentrancy Guard ───────────────────────────────────────────────

    uint256 private _locked = 1;

    /// @dev Prevents re-entrant calls to ETH-transferring functions.
    ///      Uses the lock-before-unlock pattern (status 1 = unlocked, 2 = locked).
    modifier nonReentrant() {
        require(_locked == 1, "ReentrancyGuard: reentrant call");
        _locked = 2;
        _;
        _locked = 1;
    }

    // ── Structs ──────────────────────────────────────────────────────────

    struct Competition {
        bytes32 taskId; // Target contract task ID
        uint256 prizePool; // Total ETH in escrow
        uint256 startTime;
        uint256 deadline; // Submissions close here
        address winner; // Best exploit miner
        uint256 winnerScore; // Highest severity score (1e18)
        bytes32 winnerFingerprint;
        bool settled; // True after settlement
        bool withdrawn; // True after winner claims
        uint256 submissionCount;
    }

    // ── Constants ────────────────────────────────────────────────────────

    uint256 public constant MIN_DURATION = 1 hours;
    uint256 public constant MAX_DURATION = 30 days;
    uint256 public constant MIN_PRIZE = 0.01 ether;
    uint256 public constant PROTOCOL_FEE_BPS = 500; // 5%
    uint256 public constant BPS_DENOMINATOR = 10_000;

    // ── State ────────────────────────────────────────────────────────────

    uint256 public nextCompetitionId;
    mapping(uint256 => Competition) public competitions;
    uint256 public accumulatedFees;

    /// @notice The validator address authorised to submit scores.
    address public validator;

    // ── Events ───────────────────────────────────────────────────────────

    event CompetitionCreated(
        uint256 indexed id,
        bytes32 indexed taskId,
        uint256 prizePool,
        uint256 deadline
    );
    event ScoreSubmitted(
        uint256 indexed id,
        address indexed miner,
        uint256 score,
        bytes32 fingerprint
    );
    event CompetitionSettled(
        uint256 indexed id,
        address indexed winner,
        uint256 reward
    );
    event PrizeWithdrawn(
        uint256 indexed id,
        address indexed winner,
        uint256 amount
    );
    event ValidatorUpdated(
        address indexed oldValidator,
        address indexed newValidator
    );
    event FeesWithdrawn(address indexed to, uint256 amount);

    // ── Errors ───────────────────────────────────────────────────────────

    error InvalidDuration();
    error InsufficientPrize();
    error CompetitionNotActive();
    error CompetitionNotEnded();
    error AlreadySettled();
    error NotSettled();
    error AlreadyWithdrawn();
    error NotWinner();
    error NoWinner();
    error OnlyValidator();

    // ── Modifiers ────────────────────────────────────────────────────────

    modifier onlyValidator() {
        if (msg.sender != validator) revert OnlyValidator();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    constructor(address _validator, uint256 transferDelay) Ownable2Step(transferDelay) {
        if (_validator == address(0)) revert ZeroAddress();
        validator = _validator;
    }

    // ── Admin ────────────────────────────────────────────────────────────

    /// @notice Update the authorised validator address.
    function setValidator(address _validator) external onlyOwner {
        if (_validator == address(0)) revert ZeroAddress();
        emit ValidatorUpdated(validator, _validator);
        validator = _validator;
    }

    /// @notice Withdraw accumulated protocol fees.
    function withdrawFees(address payable to) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        emit FeesWithdrawn(to, amount);
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    // ── Competition Lifecycle ────────────────────────────────────────────

    /// @notice Create a new timed competition with a funded prize pool.
    function createCompetition(
        bytes32 taskId,
        uint256 duration
    ) external payable whenNotPaused returns (uint256 id) {
        if (duration < MIN_DURATION || duration > MAX_DURATION)
            revert InvalidDuration();
        if (msg.value < MIN_PRIZE) revert InsufficientPrize();

        id = nextCompetitionId++;
        competitions[id] = Competition({
            taskId: taskId,
            prizePool: msg.value,
            startTime: block.timestamp,
            deadline: block.timestamp + duration,
            winner: address(0),
            winnerScore: 0,
            winnerFingerprint: bytes32(0),
            settled: false,
            withdrawn: false,
            submissionCount: 0
        });

        emit CompetitionCreated(
            id,
            taskId,
            msg.value,
            block.timestamp + duration
        );
    }

    /// @notice Submit a miner's score for an active competition.
    /// @dev Only callable by the authorised validator.
    function submitScore(
        uint256 competitionId,
        address miner,
        uint256 score,
        bytes32 fingerprint
    ) external onlyValidator whenNotPaused {
        if (miner == address(0)) revert ZeroAddress();
        Competition storage comp = competitions[competitionId];
        if (block.timestamp > comp.deadline) revert CompetitionNotActive();
        if (comp.settled) revert AlreadySettled();
        if (comp.startTime == 0) revert CompetitionNotActive();

        comp.submissionCount++;

        // Track highest score ─ winner takes all
        if (score > comp.winnerScore) {
            comp.winner = miner;
            comp.winnerScore = score;
            comp.winnerFingerprint = fingerprint;
        }

        emit ScoreSubmitted(competitionId, miner, score, fingerprint);
    }

    /// @notice Settle a competition after the deadline.
    /// @dev Deducts protocol fee and marks the winner's reward.
    function settle(uint256 competitionId) external whenNotPaused {
        Competition storage comp = competitions[competitionId];
        if (comp.startTime == 0) revert CompetitionNotActive();
        if (block.timestamp <= comp.deadline) revert CompetitionNotEnded();
        if (comp.settled) revert AlreadySettled();

        comp.settled = true;

        if (comp.winner == address(0)) {
            // No submissions: return prize to owner
            accumulatedFees += comp.prizePool;
            emit CompetitionSettled(competitionId, address(0), 0);
            return;
        }

        uint256 fee = (comp.prizePool * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        accumulatedFees += fee;
        uint256 reward = comp.prizePool - fee;

        emit CompetitionSettled(competitionId, comp.winner, reward);
    }

    /// @notice Winner withdraws their prize after settlement.
    function withdrawPrize(uint256 competitionId) external nonReentrant {
        Competition storage comp = competitions[competitionId];
        if (!comp.settled) revert NotSettled();
        if (comp.withdrawn) revert AlreadyWithdrawn();
        if (comp.winner == address(0)) revert NoWinner();
        if (msg.sender != comp.winner) revert NotWinner();

        comp.withdrawn = true;

        uint256 fee = (comp.prizePool * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        uint256 reward = comp.prizePool - fee;

        emit PrizeWithdrawn(competitionId, msg.sender, reward);
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "Transfer failed");
    }

    // ── View Functions ───────────────────────────────────────────────────

    /// @notice Get full competition details.
    function getCompetition(
        uint256 id
    ) external view returns (Competition memory) {
        return competitions[id];
    }

    /// @notice Check if a competition is accepting submissions.
    function isActive(uint256 id) external view returns (bool) {
        Competition storage comp = competitions[id];
        return
            comp.startTime > 0 &&
            block.timestamp <= comp.deadline &&
            !comp.settled;
    }

    /// @notice Time remaining before deadline (0 if ended).
    function timeRemaining(uint256 id) external view returns (uint256) {
        Competition storage comp = competitions[id];
        if (block.timestamp >= comp.deadline) return 0;
        return comp.deadline - block.timestamp;
    }

    /// @notice Reject unsolicited ETH to prevent funds becoming trapped.
    receive() external payable {
        revert("Treasury: use deposit functions");
    }
}
