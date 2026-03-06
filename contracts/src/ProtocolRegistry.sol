// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Pausable.sol";

/// @title ProtocolRegistry — Opt-in registry for protocols submitting contracts to the exploit subnet.
/// @notice Protocols register contract addresses, deposit bounty escrow, and enforce disclosure windows.
/// @dev Only registered contracts are valid targets. This is the legal firewall.
contract ProtocolRegistry is Pausable {
    // ── Reentrancy Guard ─────────────────────────────────────────────────

    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "ReentrancyGuard: reentrant call");
        _locked = 2;
        _;
        _locked = 1;
    }

    // ── Structs ──────────────────────────────────────────────────────────

    struct RegisteredContract {
        address protocol; // Protocol owner (can withdraw unused bounty)
        address target; // Contract address being registered
        bytes32 codeHash; // keccak256(runtime bytecode) at registration time
        uint256 bountyPool; // Wei deposited as bounty
        uint256 registeredAt; // Block timestamp of registration
        uint256 expiresAt; // Expiry (0 = no expiry)
        bool active; // Can be deactivated by protocol
    }

    struct ExploitClaim {
        address miner;
        bytes32 taskId;
        bytes32 exploitFingerprint;
        uint256 severityScore; // Fixed-point 1e18
        uint256 rewardAmount;
        uint256 claimedAt;
        bool paid;
    }

    // ── Constants ────────────────────────────────────────────────────────

    uint256 public constant DISCLOSURE_WINDOW = 72 hours;
    uint256 public constant MIN_BOUNTY = 0.01 ether;
    uint256 public constant MAX_REWARD_BPS = 9000; // 90% of bounty pool max per exploit
    uint256 public constant MAX_CLAIMS_PER_CONTRACT = 100; // Prevent unbounded exploitHistory loop

    // ── State ────────────────────────────────────────────────────────────

    uint256 public registrationCount;

    // contractHash => RegisteredContract
    mapping(bytes32 => RegisteredContract) public registry;
    // contractHash => exploitFingerprint => ExploitClaim
    mapping(bytes32 => mapping(bytes32 => ExploitClaim)) public claims;
    // contractHash => list of exploit fingerprints (for enumeration)
    mapping(bytes32 => bytes32[]) public exploitHistory;
    // Whitelist of validator addresses
    mapping(address => bool) public validators;

    // ── Events ───────────────────────────────────────────────────────────

    event ContractRegistered(
        bytes32 indexed contractHash,
        address indexed protocol,
        address target,
        uint256 bounty
    );
    event ContractDeactivated(bytes32 indexed contractHash);
    event BountyAdded(bytes32 indexed contractHash, uint256 amount);
    event ExploitClaimed(
        bytes32 indexed contractHash,
        bytes32 indexed exploitFingerprint,
        address miner,
        uint256 reward
    );
    event ExploitRewardPaid(
        bytes32 indexed contractHash,
        bytes32 indexed exploitFingerprint,
        address miner,
        uint256 amount
    );
    event ValidatorUpdated(address indexed validator, bool status);
    event BountyWithdrawn(bytes32 indexed contractHash, uint256 amount);

    // ── Errors ───────────────────────────────────────────────────────────

    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientBounty();
    error ContractInactive();
    error ContractStillActive();
    error ExploitAlreadyClaimed();
    error DisclosureWindowActive();
    error InvalidValidator();
    error InvalidSeverity();
    error PaymentFailed();
    error TooManyClaims();
    error ContractExpired();
    error InvalidStartIndex();
    error InvalidExpiry();
    error ContractNotActive();

    // ── Modifiers ────────────────────────────────────────────────────────

    modifier onlyValidator() {
        if (!validators[msg.sender]) revert InvalidValidator();
        _;
    }

    modifier onlyProtocol(bytes32 contractHash) {
        if (registry[contractHash].protocol != msg.sender)
            revert Unauthorized();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable2Step(0) {}

    // ── Protocol Functions ───────────────────────────────────────────────

    /// @notice Register a contract for exploit testing. Must deposit minimum bounty.
    /// @param target The deployed contract address to register.
    /// @param expiresAt Optional expiry timestamp (0 = no expiry).
    function registerContract(
        address target,
        uint256 expiresAt
    ) external payable whenNotPaused {
        if (target == address(0)) revert ZeroAddress();
        if (msg.value < MIN_BOUNTY) revert InsufficientBounty();
        if (expiresAt != 0 && expiresAt <= block.timestamp)
            revert InvalidExpiry();

        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(target)
        }

        bytes32 contractHash = keccak256(abi.encodePacked(target, codeHash));
        if (registry[contractHash].active) revert AlreadyRegistered();

        registry[contractHash] = RegisteredContract({
            protocol: msg.sender,
            target: target,
            codeHash: codeHash,
            bountyPool: msg.value,
            registeredAt: block.timestamp,
            expiresAt: expiresAt,
            active: true
        });

        registrationCount++;
        emit ContractRegistered(contractHash, msg.sender, target, msg.value);
    }

    /// @notice Add more bounty to an existing registration.
    function addBounty(
        bytes32 contractHash
    ) external payable onlyProtocol(contractHash) {
        if (!registry[contractHash].active) revert ContractInactive();
        registry[contractHash].bountyPool += msg.value;
        emit BountyAdded(contractHash, msg.value);
    }

    /// @notice Deactivate a registered contract. Cannot withdraw bounty until all disclosure windows close.
    function deactivateContract(
        bytes32 contractHash
    ) external onlyProtocol(contractHash) {
        if (!registry[contractHash].active) revert ContractNotActive();
        registry[contractHash].active = false;
        emit ContractDeactivated(contractHash);
    }

    /// @notice Withdraw remaining bounty from a deactivated contract (after disclosure windows).
    /// @param contractHash The hash of the registered contract.
    /// @param startIndex Starting index into the claims history for pagination.
    ///        Call repeatedly with increasing startIndex until all claims are checked.
    function withdrawBounty(
        bytes32 contractHash,
        uint256 startIndex
    ) external onlyProtocol(contractHash) nonReentrant {
        RegisteredContract storage reg = registry[contractHash];
        if (reg.active) revert ContractStillActive();

        // Enforce: all existing claims must be paid or disclosure window expired
        // Process up to MAX_CLAIMS_PER_WITHDRAWAL at a time to bound gas
        uint256 maxPerCall = 20;
        bytes32[] storage history = exploitHistory[contractHash];

        // When there are claims, startIndex must be within bounds
        if (history.length > 0 && startIndex >= history.length)
            revert InvalidStartIndex();
        // When there are no claims, startIndex must be 0
        if (history.length == 0 && startIndex != 0) revert InvalidStartIndex();

        uint256 end = startIndex + maxPerCall;
        if (end > history.length) end = history.length;

        for (uint256 i = startIndex; i < end; i++) {
            ExploitClaim storage c = claims[contractHash][history[i]];
            if (c.miner != address(0) && !c.paid) {
                if (block.timestamp < c.claimedAt + DISCLOSURE_WINDOW)
                    revert DisclosureWindowActive();
            }
        }

        // Only transfer if all claims verified (final page)
        if (end >= history.length) {
            uint256 amount = reg.bountyPool;
            reg.bountyPool = 0;

            (bool ok, ) = msg.sender.call{value: amount}("");
            if (!ok) revert PaymentFailed();

            emit BountyWithdrawn(contractHash, amount);
        }
    }

    // ── Validator Functions ──────────────────────────────────────────────

    /// @notice Record a validated exploit claim and compute reward.
    /// @dev Only callable by registered validators. Enforces first-claim priority.
    function recordExploit(
        bytes32 contractHash,
        bytes32 exploitFingerprint,
        address miner,
        uint256 severityScore // 1e18 fixed-point (0 to 1e18)
    ) external onlyValidator whenNotPaused {
        if (miner == address(0)) revert ZeroAddress();
        if (severityScore > 1e18) revert InvalidSeverity();
        RegisteredContract storage reg = registry[contractHash];
        if (!reg.active) revert ContractInactive();
        if (reg.expiresAt != 0 && block.timestamp > reg.expiresAt)
            revert ContractExpired();
        if (claims[contractHash][exploitFingerprint].miner != address(0))
            revert ExploitAlreadyClaimed();
        if (exploitHistory[contractHash].length >= MAX_CLAIMS_PER_CONTRACT)
            revert TooManyClaims();

        // Reward = (bountyPool * severity / 1e18) * MAX_REWARD_BPS / 10000
        // Split multiplication to prevent overflow for large bounty pools (>1000 ETH).
        uint256 scaledSeverity = (reg.bountyPool * severityScore) / 1e18;
        uint256 reward = (scaledSeverity * MAX_REWARD_BPS) / 10000;
        if (reward > reg.bountyPool) reward = reg.bountyPool;

        claims[contractHash][exploitFingerprint] = ExploitClaim({
            miner: miner,
            taskId: contractHash,
            exploitFingerprint: exploitFingerprint,
            severityScore: severityScore,
            rewardAmount: reward,
            claimedAt: block.timestamp,
            paid: false
        });

        exploitHistory[contractHash].push(exploitFingerprint);
        reg.bountyPool -= reward;

        emit ExploitClaimed(contractHash, exploitFingerprint, miner, reward);
    }

    /// @notice Pay out exploit reward after disclosure window.
    /// @dev Rewards are snapshotted at claim time, so payment is allowed even
    ///      if the registered contract has since expired — miners should not
    ///      lose their earned reward due to expiry.
    function payExploitReward(
        bytes32 contractHash,
        bytes32 exploitFingerprint
    ) external nonReentrant whenNotPaused {
        ExploitClaim storage claim = claims[contractHash][exploitFingerprint];
        if (claim.miner == address(0)) revert NotRegistered();
        if (claim.paid) revert ExploitAlreadyClaimed();
        if (block.timestamp < claim.claimedAt + DISCLOSURE_WINDOW)
            revert DisclosureWindowActive();

        claim.paid = true;
        (bool ok, ) = claim.miner.call{value: claim.rewardAmount}("");
        if (!ok) revert PaymentFailed();

        emit ExploitRewardPaid(
            contractHash,
            exploitFingerprint,
            claim.miner,
            claim.rewardAmount
        );
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function setValidator(address validator, bool status) external onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        validators[validator] = status;
        emit ValidatorUpdated(validator, status);
    }

    /// @notice Withdraw remaining bounty in a single call (checks ALL claims).
    /// @dev Convenience wrapper around withdrawBounty for small claim histories.
    ///      Reverts if history exceeds MAX_CLAIMS_PER_CONTRACT (use paginated version instead).
    function withdrawBountyAll(
        bytes32 contractHash
    ) external onlyProtocol(contractHash) nonReentrant {
        RegisteredContract storage reg = registry[contractHash];
        if (reg.active) revert ContractStillActive();

        bytes32[] storage history = exploitHistory[contractHash];
        for (uint256 i = 0; i < history.length; i++) {
            ExploitClaim storage c = claims[contractHash][history[i]];
            if (c.miner != address(0) && !c.paid) {
                if (block.timestamp < c.claimedAt + DISCLOSURE_WINDOW)
                    revert DisclosureWindowActive();
            }
        }

        uint256 amount = reg.bountyPool;
        reg.bountyPool = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert PaymentFailed();

        emit BountyWithdrawn(contractHash, amount);
    }

    // ── View Functions ───────────────────────────────────────────────────

    function isRegistered(bytes32 contractHash) external view returns (bool) {
        return registry[contractHash].active;
    }

    function getExploitCount(
        bytes32 contractHash
    ) external view returns (uint256) {
        return exploitHistory[contractHash].length;
    }

    function getContractHash(address target) external view returns (bytes32) {
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(target)
        }
        return keccak256(abi.encodePacked(target, codeHash));
    }

    function getRemainingBounty(
        bytes32 contractHash
    ) external view returns (uint256) {
        return registry[contractHash].bountyPool;
    }
}
