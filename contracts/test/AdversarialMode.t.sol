// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/stage3/AdversarialMode.sol";
import "../src/Ownable2Step.sol";

/// @title AdversarialModeTest — Foundry tests for InvariantRegistry + AdversarialScoring.
contract AdversarialModeTest is Test {
    InvariantRegistry public registry;
    AdversarialScoring public scoring;

    address owner = address(this);
    address classA = address(0xA);
    address classB = address(0xB);
    address validator1 = address(0xE1);

    bytes32 constant TARGET_HASH = keccak256("TargetContract");

    function setUp() public {
        registry = new InvariantRegistry(0);
        scoring = new AdversarialScoring(address(registry), 0);

        // Register the AdversarialScoring contract as a validator on the registry
        // (required for processChallenge → recordChallenge to succeed)
        registry.setValidator(address(scoring), true);
        registry.setValidator(validator1, true);
        registry.setValidator(classA, true); // Class A submits invariants

        // Register test contract as a validator on scoring
        // (processChallenge now requires onlyValidator, not onlyOwner)
        scoring.setValidator(address(this), true);
        scoring.setValidator(validator1, true);
    }

    // ── InvariantRegistry ───────────────────────────────────────────────

    function test_submitInvariant() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "Balance must never decrease",
            "balanceOf(address) >= initial",
            hex"deadbeef"
        );
        assertEq(id, 0);
        assertEq(registry.propertyCount(), 1);
    }

    function test_recordChallenge_hold() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        vm.prank(validator1);
        registry.recordChallenge(id, false);

        uint256 score = registry.getInvariantScore(id);
        assertEq(score, 1e18); // 1/1 = 100%
    }

    function test_recordChallenge_broken() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        vm.prank(validator1);
        registry.recordChallenge(id, true);

        uint256 score = registry.getInvariantScore(id);
        assertEq(score, 0); // 0 holds / 1 challenge = 0
    }

    function test_recordChallenge_nonValidator_reverts() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        address nobody = address(0x999);
        vm.prank(nobody);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        registry.recordChallenge(id, false);
    }

    function test_deactivateInvariant() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        vm.prank(validator1);
        registry.deactivateInvariant(id);

        // Subsequent challenge should revert
        vm.prank(validator1);
        vm.expectRevert(InvariantRegistry.InvariantInactive.selector);
        registry.recordChallenge(id, false);
    }

    function test_invariantScore_untested() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        uint256 score = registry.getInvariantScore(id);
        assertEq(score, 1e18); // Neutral for untested
    }

    function test_setValidator_nonOwner_reverts() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        registry.setValidator(address(0x123), true);
    }

    function test_submitInvariant_nonValidator_reverts() public {
        address nobody = address(0x999);
        vm.prank(nobody);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        registry.submitInvariant(classA, TARGET_HASH, "inv", "cond", hex"");
    }

    function test_transferOwnership_zeroAddress_reverts() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    function test_transferOwnership() public {
        address newOwner = address(0x42);
        // Step 1: Initiate transfer
        registry.transferOwnership(newOwner);
        // Owner is still the test contract
        assertEq(registry.owner(), address(this));

        // Step 2: New owner accepts
        vm.prank(newOwner);
        registry.acceptOwnership();
        assertEq(registry.owner(), newOwner);

        // Old owner can no longer set validators
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        registry.setValidator(address(0x99), true);

        // New owner can
        vm.prank(newOwner);
        registry.setValidator(address(0x99), true);
    }

    // ── AdversarialScoring ──────────────────────────────────────────────

    function test_processChallenge_broken() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        scoring.processChallenge(id, classA, classB, true);

        assertEq(scoring.classBScores(classB), 1000); // W_BREACH_REWARD
        assertEq(scoring.classAScores(classA), -500); // W_BREACH_PENALTY
    }

    function test_processChallenge_held() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        scoring.processChallenge(id, classA, classB, false);

        assertEq(scoring.classAScores(classA), 100); // W_HOLD_REWARD
        assertEq(scoring.classBScores(classB), 10); // W_FAILED_CHALLENGE
    }

    function test_processChallenge_nonValidator_reverts() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        vm.prank(address(0xBEEF));
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        scoring.processChallenge(id, classA, classB, true);
    }

    function test_processChallenge_owner_without_validator_role_reverts()
        public
    {
        // Deploy fresh scoring without registering owner as validator
        AdversarialScoring freshScoring = new AdversarialScoring(
            address(registry), 0
        );
        registry.setValidator(address(freshScoring), true);

        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        // Owner is address(this) but NOT a validator on freshScoring
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        freshScoring.processChallenge(id, classA, classB, true);
    }

    function test_processChallenge_succeeds_for_registered_validator() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        vm.prank(validator1);
        scoring.processChallenge(id, classA, classB, true);

        assertEq(scoring.classBScores(classB), 1000);
        assertEq(scoring.classAScores(classA), -500);
    }

    function test_scoring_setValidator_nonOwner_reverts() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        scoring.setValidator(address(0x123), true);
    }

    function test_scoring_removeValidator_blocks_processChallenge() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        // Remove validator1
        scoring.setValidator(validator1, false);

        vm.prank(validator1);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        scoring.processChallenge(id, classA, classB, false);
    }

    function test_scoring_transferOwnership_zeroAddress_reverts() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        scoring.transferOwnership(address(0));
    }

    function test_multipleRounds_scoring() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        // Round 1: invariant holds
        scoring.processChallenge(id, classA, classB, false);
        // Round 2: invariant broken
        scoring.processChallenge(id, classA, classB, true);
        // Round 3: invariant holds
        scoring.processChallenge(id, classA, classB, false);

        // Class A: +100 - 500 + 100 = -300
        assertEq(scoring.classAScores(classA), -300);
        // Class B: +10 + 1000 + 10 = 1020
        assertEq(scoring.classBScores(classB), 1020);

        // Invariant score: 2 holds / 3 challenges
        uint256 invScore = registry.getInvariantScore(id);
        uint256 expected = (uint256(2) * 1e18) / uint256(3);
        assertEq(invScore, expected);
    }

    function test_scoreFloor_classA() public {
        vm.prank(classA);
        uint256 id = registry.submitInvariant(classA,
            TARGET_HASH,
            "inv",
            "cond",
            hex""
        );

        int256 minScore = scoring.MIN_SCORE();

        // Repeatedly penalize classA to drive score very low
        for (uint256 i = 0; i < 500; i++) {
            scoring.processChallenge(id, classA, classB, true);
        }

        // Score should be clamped at MIN_SCORE, not lower
        assertGe(scoring.classAScores(classA), minScore);
    }

    // ── Bounds Check Tests ──────────────────────────────────────────────

    function test_recordChallenge_invalidId_reverts() public {
        vm.prank(validator1);
        vm.expectRevert(InvariantRegistry.InvalidPropertyId.selector);
        registry.recordChallenge(999, false);
    }

    function test_getInvariantScore_invalidId_reverts() public {
        vm.expectRevert(InvariantRegistry.InvalidPropertyId.selector);
        registry.getInvariantScore(0); // No invariants submitted yet
    }

    function test_deactivateInvariant_invalidId_reverts() public {
        vm.prank(validator1);
        vm.expectRevert(InvariantRegistry.InvalidPropertyId.selector);
        registry.deactivateInvariant(42);
    }

    function testFuzz_recordChallenge_outOfBounds(uint256 id) public {
        // Submit one invariant so propertyCount == 1
        vm.prank(classA);
        registry.submitInvariant(classA, TARGET_HASH, "inv", "cond", hex"");

        if (id >= 1) {
            vm.prank(validator1);
            vm.expectRevert(InvariantRegistry.InvalidPropertyId.selector);
            registry.recordChallenge(id, false);
        }
    }
}
