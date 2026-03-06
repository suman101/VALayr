// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ExploitRegistry.sol";
import "../src/Treasury.sol";

// ── ExploitRegistry Invariant Tests ──────────────────────────────────────

/// @dev Handler contract for bounded calls into ExploitRegistry.
contract ExploitRegistryHandler is Test {
    ExploitRegistry public reg;
    uint256 public ghostTotalRecorded;
    uint256 public ghostUniqueRecorded;
    bytes32 constant TASK_ID = keccak256("inv-task");

    constructor(ExploitRegistry _reg) {
        reg = _reg;
    }

    function recordExploit(uint256 severitySeed, uint256 fpSeed) external {
        uint256 severity = bound(severitySeed, 1, 1e18);
        bytes32 fp = keccak256(abi.encode("inv-fp", fpSeed));

        bool isNew = reg.isFirstSubmission(TASK_ID, fp);

        reg.recordExploit(TASK_ID, fp, msg.sender, severity, 5);
        ghostTotalRecorded++;
        if (isNew) ghostUniqueRecorded++;
    }
}

/// @title ExploitRegistryInvariantTest
contract ExploitRegistryInvariantTest is Test {
    ExploitRegistry public reg;
    ExploitRegistryHandler public handler;

    function setUp() public {
        reg = new ExploitRegistry();
        reg.setValidator(address(this), true);

        handler = new ExploitRegistryHandler(reg);
        // Give handler validator permissions so it can record
        reg.setValidator(address(handler), true);

        targetContract(address(handler));
    }

    /// @notice totalExploits counter must never decrease.
    function invariant_totalExploitsNeverExceedsRecorded() public view {
        assertEq(reg.totalExploits(), handler.ghostTotalRecorded());
    }

    /// @notice uniqueExploitCount must always be <= totalExploits.
    function invariant_uniqueLeqTotal() public view {
        bytes32 taskId = keccak256("inv-task");
        assertLe(reg.uniqueExploitCount(taskId), reg.totalExploits());
    }

    /// @notice uniqueExploitCount must match handler's ghost unique count.
    function invariant_uniqueMatchesGhost() public view {
        bytes32 taskId = keccak256("inv-task");
        assertEq(reg.uniqueExploitCount(taskId), handler.ghostUniqueRecorded());
    }
}

// ── Treasury Invariant Tests ─────────────────────────────────────────────

/// @dev Handler contract for bounded calls into Treasury.
contract TreasuryHandler is Test {
    Treasury public treasury;
    address public validatorAddr;
    uint256 public ghostTotalDeposited;
    uint256 public ghostTotalWithdrawn;
    uint256 public ghostCompetitionsCreated;

    constructor(Treasury _treasury, address _validator) {
        treasury = _treasury;
        validatorAddr = _validator;
    }

    function createCompetition(uint256 durationSeed) external payable {
        uint256 prize = bound(msg.value, 0.01 ether, 10 ether);
        uint256 duration = bound(durationSeed, 1 hours, 30 days);

        // Deal ether to this contract for the creation
        deal(address(this), prize);
        treasury.createCompetition{value: prize}(bytes32(0), duration);
        ghostTotalDeposited += prize;
        ghostCompetitionsCreated++;
    }

    receive() external payable {}
}

/// @title TreasuryInvariantTest
contract TreasuryInvariantTest is Test {
    Treasury public treasury;
    TreasuryHandler public handler;
    address public validatorAddr;

    function setUp() public {
        validatorAddr = makeAddr("validator");
        treasury = new Treasury(validatorAddr);

        handler = new TreasuryHandler(treasury, validatorAddr);

        targetContract(address(handler));
    }

    /// @notice Treasury balance must always be >= accumulated fees.
    function invariant_balanceGeqFees() public view {
        assertGe(address(treasury).balance, treasury.accumulatedFees());
    }

    /// @notice nextCompetitionId must match handler's ghost count.
    function invariant_competitionIdMatchesGhost() public view {
        assertEq(
            treasury.nextCompetitionId(),
            handler.ghostCompetitionsCreated()
        );
    }
}
