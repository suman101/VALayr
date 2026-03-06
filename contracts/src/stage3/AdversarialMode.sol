// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../Pausable.sol";

/// @title AdversarialMode — Stage 3 invariant writer vs. breaker system.
/// @dev Month 5-6. Two miner classes compete:
///   Class A: Submit invariants (formal properties)
///   Class B: Attempt to break invariants
///
/// If exploit breaks invariant → B wins
/// If invariant holds under adversarial attempts → A gains score
///
/// This is the actual moat. Evolutionary pressure.

/// ── Invariant Registry ──────────────────────────────────────────────────────
contract InvariantRegistry is Pausable {
    struct Invariant {
        address submitter; // Class A miner
        bytes32 targetContractHash; // Which contract this invariant covers
        string description; // Human-readable description
        string solidityCondition; // Solidity boolean expression
        bytes compiledCheck; // ABI-encoded check function
        uint256 submittedAt;
        uint256 challengeCount; // Times this invariant was challenged
        uint256 breachCount; // Times it was successfully broken
        uint256 holdCount; // Times it held under challenge
        bool active;
    }

    uint256 public propertyCount;
    mapping(uint256 => Invariant) public properties;
    mapping(address => bool) public validators;

    event InvariantSubmitted(
        uint256 indexed id,
        address indexed submitter,
        bytes32 targetContract
    );
    event InvariantChallenged(
        uint256 indexed id,
        address indexed challenger,
        bool broken
    );
    event InvariantDeactivated(uint256 indexed id);
    event ValidatorUpdated(address indexed validator, bool status);

    error InvariantNotFound();
    error InvariantInactive();
    error InvalidPropertyId();

    constructor(uint256 transferDelay) Ownable2Step(transferDelay) {}

    modifier onlyValidator() {
        if (!validators[msg.sender]) revert Unauthorized();
        _;
    }

    /// @notice Class A miner submits an invariant (called by validator on miner's behalf).
    function submitInvariant(
        address miner,
        bytes32 targetContractHash,
        string calldata description,
        string calldata solidityCondition,
        bytes calldata compiledCheck
    ) external onlyValidator whenNotPaused returns (uint256 id) {
        if (miner == address(0)) revert ZeroAddress();
        id = propertyCount++;
        properties[id] = Invariant({
            submitter: miner,
            targetContractHash: targetContractHash,
            description: description,
            solidityCondition: solidityCondition,
            compiledCheck: compiledCheck,
            submittedAt: block.timestamp,
            challengeCount: 0,
            breachCount: 0,
            holdCount: 0,
            active: true
        });
        emit InvariantSubmitted(id, miner, targetContractHash);
    }

    /// @notice Record challenge result (from validator consensus).
    /// @param broken True if exploit broke the invariant (Class B wins).
    function recordChallenge(
        uint256 id,
        bool broken
    ) external onlyValidator whenNotPaused {
        if (id >= propertyCount) revert InvalidPropertyId();
        Invariant storage inv = properties[id];
        if (!inv.active) revert InvariantInactive();

        inv.challengeCount++;
        if (broken) {
            inv.breachCount++;
        } else {
            inv.holdCount++;
        }

        emit InvariantChallenged(id, msg.sender, broken);
    }

    /// @notice Get invariant strength score.
    /// @dev Score = holdCount / challengeCount (higher = stronger)
    function getInvariantScore(
        uint256 id
    ) external view returns (uint256 score) {
        if (id >= propertyCount) revert InvalidPropertyId();
        Invariant storage inv = properties[id];
        if (inv.challengeCount == 0) return 1e18; // Untested = neutral
        return (inv.holdCount * 1e18) / inv.challengeCount;
    }

    /// @notice Deactivate an invariant (e.g., if proven trivially true).
    function deactivateInvariant(uint256 id) external onlyValidator {
        if (id >= propertyCount) revert InvalidPropertyId();
        properties[id].active = false;
        emit InvariantDeactivated(id);
    }

    function setValidator(address v, bool status) external onlyOwner {
        validators[v] = status;
        emit ValidatorUpdated(v, status);
    }
}

/// ── Adversarial Scoring ─────────────────────────────────────────────────────
/// @dev Computes rewards for both miner classes.
contract AdversarialScoring is Pausable {
    InvariantRegistry public registry;

    // Scoring weights for Class A (invariant writers)
    int256 public constant W_HOLD_REWARD = 100; // Points per successful defense
    int256 public constant W_BREACH_PENALTY = 500; // Points lost per breach

    // Scoring weights for Class B (exploit writers)
    int256 public constant W_BREACH_REWARD = 1000; // Points per successful breach
    int256 public constant W_FAILED_CHALLENGE = 10; // Small consolation for trying

    // Score floor to prevent unbounded negatives (overflow-safe)
    int256 public constant MIN_SCORE = type(int256).min / 2;

    mapping(address => int256) public classAScores;
    mapping(address => int256) public classBScores;
    mapping(address => bool) public validators;

    event ScoreUpdated(address indexed miner, string class_, int256 newScore);
    event ValidatorUpdated(address indexed validator, bool status);

    constructor(address _registry, uint256 transferDelay) Ownable2Step(transferDelay) {
        registry = InvariantRegistry(_registry);
    }

    modifier onlyValidator() {
        if (!validators[msg.sender]) revert Unauthorized();
        _;
    }

    /// @notice Add or remove a validator address.
    function setValidator(address v, bool status) external onlyOwner {
        validators[v] = status;
        emit ValidatorUpdated(v, status);
    }

    /// @notice Update scores after a challenge round.
    function processChallenge(
        uint256 invariantId,
        address classAMiner, // Invariant submitter
        address classBMiner, // Exploit submitter
        bool broken
    ) external onlyValidator whenNotPaused {
        // Record challenge result in the invariant registry
        registry.recordChallenge(invariantId, broken);

        if (broken) {
            // Class B wins: exploit broke the invariant
            classBScores[classBMiner] += W_BREACH_REWARD;
            classAScores[classAMiner] -= W_BREACH_PENALTY;
            if (classAScores[classAMiner] < MIN_SCORE)
                classAScores[classAMiner] = MIN_SCORE;
            emit ScoreUpdated(classBMiner, "B", classBScores[classBMiner]);
            emit ScoreUpdated(classAMiner, "A", classAScores[classAMiner]);
        } else {
            // Class A wins: invariant held
            classAScores[classAMiner] += W_HOLD_REWARD;
            classBScores[classBMiner] += W_FAILED_CHALLENGE;
            emit ScoreUpdated(classAMiner, "A", classAScores[classAMiner]);
            emit ScoreUpdated(classBMiner, "B", classBScores[classBMiner]);
        }
    }

    function getClassAScore(address miner) external view returns (int256) {
        return classAScores[miner];
    }

    function getClassBScore(address miner) external view returns (int256) {
        return classBScores[miner];
    }
}
