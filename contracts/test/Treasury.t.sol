// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/Treasury.sol";
import "../src/Ownable2Step.sol";

contract TreasuryTest is Test {
    Treasury public treasury;
    address public owner;
    address public validatorAddr;
    address public miner1;
    address public miner2;

    function setUp() public {
        owner = address(this);
        validatorAddr = makeAddr("validator");
        miner1 = makeAddr("miner1");
        miner2 = makeAddr("miner2");
        treasury = new Treasury(validatorAddr, 0);
    }

    // ── createCompetition ────────────────────────────────────────────────

    function test_createCompetition() public {
        bytes32 taskId = keccak256("task1");
        uint256 id = treasury.createCompetition{value: 1 ether}(taskId, 1 days);
        assertEq(id, 0);

        Treasury.Competition memory comp = treasury.getCompetition(0);
        assertEq(comp.taskId, taskId);
        assertEq(comp.prizePool, 1 ether);
        assertEq(comp.deadline, block.timestamp + 1 days);
        assertFalse(comp.settled);
        assertTrue(treasury.isActive(0));
    }

    function test_createCompetition_tooShort_reverts() public {
        vm.expectRevert(Treasury.InvalidDuration.selector);
        treasury.createCompetition{value: 1 ether}(bytes32(0), 30 minutes);
    }

    function test_createCompetition_tooLong_reverts() public {
        vm.expectRevert(Treasury.InvalidDuration.selector);
        treasury.createCompetition{value: 1 ether}(bytes32(0), 31 days);
    }

    function test_createCompetition_insufficientPrize_reverts() public {
        vm.expectRevert(Treasury.InsufficientPrize.selector);
        treasury.createCompetition{value: 0.001 ether}(bytes32(0), 1 days);
    }

    // ── submitScore ──────────────────────────────────────────────────────

    function test_submitScore() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 5e17, keccak256("fp1"));

        Treasury.Competition memory comp = treasury.getCompetition(0);
        assertEq(comp.winner, miner1);
        assertEq(comp.winnerScore, 5e17);
        assertEq(comp.submissionCount, 1);
    }

    function test_submitScore_higherScoreWins() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.startPrank(validatorAddr);
        treasury.submitScore(0, miner1, 5e17, keccak256("fp1"));
        treasury.submitScore(0, miner2, 9e17, keccak256("fp2"));
        vm.stopPrank();

        Treasury.Competition memory comp = treasury.getCompetition(0);
        assertEq(comp.winner, miner2);
        assertEq(comp.winnerScore, 9e17);
        assertEq(comp.submissionCount, 2);
    }

    function test_submitScore_nonValidator_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(miner1);
        vm.expectRevert(Treasury.OnlyValidator.selector);
        treasury.submitScore(0, miner1, 5e17, keccak256("fp1"));
    }

    function test_submitScore_afterDeadline_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(validatorAddr);
        vm.expectRevert(Treasury.CompetitionNotActive.selector);
        treasury.submitScore(0, miner1, 5e17, keccak256("fp1"));
    }

    // ── settle ───────────────────────────────────────────────────────────

    function test_settle() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 9e17, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        Treasury.Competition memory comp = treasury.getCompetition(0);
        assertTrue(comp.settled);
        assertEq(comp.winner, miner1);
    }

    function test_settle_beforeDeadline_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.expectRevert(Treasury.CompetitionNotEnded.selector);
        treasury.settle(0);
    }

    function test_settle_twice_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);
        vm.expectRevert(Treasury.AlreadySettled.selector);
        treasury.settle(0);
    }

    function test_settle_noSubmissions_feesToOwner() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        // Full prize goes to accumulated fees (returned to owner)
        assertEq(treasury.accumulatedFees(), 1 ether);
    }

    // ── withdrawPrize ────────────────────────────────────────────────────

    function test_withdrawPrize() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 9e17, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        uint256 preBal = miner1.balance;
        vm.prank(miner1);
        treasury.withdrawPrize(0);

        // 1 ether - 5% fee = 0.95 ether
        uint256 expectedReward = 0.95 ether;
        assertEq(miner1.balance - preBal, expectedReward);
        assertEq(treasury.accumulatedFees(), 0.05 ether);
    }

    function test_withdrawPrize_notWinner_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 9e17, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        vm.prank(miner2);
        vm.expectRevert(Treasury.NotWinner.selector);
        treasury.withdrawPrize(0);
    }

    function test_withdrawPrize_notSettled_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.prank(miner1);
        vm.expectRevert(Treasury.NotSettled.selector);
        treasury.withdrawPrize(0);
    }

    function test_withdrawPrize_twice_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 9e17, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        vm.prank(miner1);
        treasury.withdrawPrize(0);

        vm.prank(miner1);
        vm.expectRevert(Treasury.AlreadyWithdrawn.selector);
        treasury.withdrawPrize(0);
    }

    // ── setValidator ─────────────────────────────────────────────────────

    function test_setValidator() public {
        address newValidator = makeAddr("newValidator");
        treasury.setValidator(newValidator);
        assertEq(treasury.validator(), newValidator);
    }

    function test_setValidator_nonOwner_reverts() public {
        vm.prank(miner1);
        vm.expectRevert();
        treasury.setValidator(miner1);
    }

    function test_setValidator_zero_reverts() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        treasury.setValidator(address(0));
    }

    // ── withdrawFees ─────────────────────────────────────────────────────

    function test_withdrawFees() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 9e17, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        address payable recipient = payable(makeAddr("feeRecipient"));
        uint256 preBal = recipient.balance;
        treasury.withdrawFees(recipient);
        assertEq(recipient.balance - preBal, 0.05 ether);
        assertEq(treasury.accumulatedFees(), 0);
    }

    // ── View helpers ─────────────────────────────────────────────────────

    function test_isActive() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        assertTrue(treasury.isActive(0));

        vm.warp(block.timestamp + 1 days + 1);
        assertFalse(treasury.isActive(0));
    }

    function test_timeRemaining() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        assertEq(treasury.timeRemaining(0), 1 days);

        vm.warp(block.timestamp + 12 hours);
        assertEq(treasury.timeRemaining(0), 12 hours);

        vm.warp(block.timestamp + 12 hours + 1);
        assertEq(treasury.timeRemaining(0), 0);
    }

    // ── Fuzz ─────────────────────────────────────────────────────────────

    // ── SC-7: Edge Cases ─────────────────────────────────────────────────

    function test_submitScore_zeroAddressMiner_reverts() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.prank(validatorAddr);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        treasury.submitScore(0, address(0), 5e17, keccak256("fp0"));
    }

    function test_submitScore_nonExistentCompetition_reverts() public {
        vm.prank(validatorAddr);
        vm.expectRevert(Treasury.CompetitionNotActive.selector);
        treasury.submitScore(999, miner1, 5e17, keccak256("fp0"));
    }

    function test_settle_noSubmissions_noWinnerWithdraw() public {
        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);
        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        vm.prank(miner1);
        vm.expectRevert(Treasury.NoWinner.selector);
        treasury.withdrawPrize(0);
    }

    // ── Fuzz ─────────────────────────────────────────────────────────────

    function testFuzz_prizeDistribution(uint256 prize) public {
        prize = bound(prize, 0.01 ether, 1000 ether);

        treasury.createCompetition{value: prize}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 1e18, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        uint256 expectedFee = (prize * 500) / 10_000;
        uint256 expectedReward = prize - expectedFee;

        uint256 preBal = miner1.balance;
        vm.prank(miner1);
        treasury.withdrawPrize(0);
        assertEq(miner1.balance - preBal, expectedReward);
        assertEq(treasury.accumulatedFees(), expectedFee);
    }

    /// @notice Fuzz: any valid duration creates a competition whose deadline math is correct.
    function testFuzz_createCompetition_duration(uint256 duration) public {
        duration = bound(duration, 1 hours, 30 days);
        uint256 t0 = block.timestamp;
        uint256 id = treasury.createCompetition{value: 1 ether}(
            bytes32(0),
            duration
        );
        Treasury.Competition memory comp = treasury.getCompetition(id);
        assertEq(comp.deadline, t0 + duration);
        assertEq(comp.prizePool, 1 ether);
        assertTrue(treasury.isActive(id));
    }

    /// @notice Fuzz: highest-scoring miner always wins regardless of submission order.
    function testFuzz_highestScoreWins(uint256 scoreA, uint256 scoreB) public {
        scoreA = bound(scoreA, 1, 1e18);
        scoreB = bound(scoreB, 1, 1e18);

        treasury.createCompetition{value: 1 ether}(bytes32(0), 1 days);

        vm.startPrank(validatorAddr);
        treasury.submitScore(0, miner1, scoreA, keccak256("fpA"));
        treasury.submitScore(0, miner2, scoreB, keccak256("fpB"));
        vm.stopPrank();

        Treasury.Competition memory comp = treasury.getCompetition(0);
        if (scoreB > scoreA) {
            assertEq(comp.winner, miner2);
            assertEq(comp.winnerScore, scoreB);
        } else {
            assertEq(comp.winner, miner1);
            assertEq(comp.winnerScore, scoreA);
        }
    }

    /// @notice Fuzz: fee + reward always equals prizePool (no rounding loss beyond 1 wei).
    function testFuzz_feeRewardSumMatchesPrize(uint256 prize) public {
        prize = bound(prize, 0.01 ether, 1000 ether);

        treasury.createCompetition{value: prize}(bytes32(0), 1 days);

        vm.prank(validatorAddr);
        treasury.submitScore(0, miner1, 1e18, keccak256("fp1"));

        vm.warp(block.timestamp + 1 days + 1);
        treasury.settle(0);

        uint256 fee = treasury.accumulatedFees();
        uint256 preBal = miner1.balance;
        vm.prank(miner1);
        treasury.withdrawPrize(0);
        uint256 reward = miner1.balance - preBal;

        assertEq(fee + reward, prize);
    }

    receive() external payable {}
}
