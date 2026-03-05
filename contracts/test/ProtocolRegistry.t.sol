// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ProtocolRegistry.sol";

/// @title ProtocolRegistryTest — Foundry tests for the Protocol Registry.
contract ProtocolRegistryTest is Test {
    ProtocolRegistry public registry;

    address constant PROTOCOL = address(0x1111);
    address constant VALIDATOR = address(0x2222);
    address constant MINER = address(0x3333);
    address constant TARGET = address(0xDEAD);

    function setUp() public {
        registry = new ProtocolRegistry();
        registry.setValidator(VALIDATOR, true);
    }

    // ── Registration Tests ───────────────────────────────────────────────

    function test_registerContract() public {
        // Deploy a dummy contract to get a valid extcodehash
        DummyTarget dummy = new DummyTarget();

        // Register with minimum bounty
        registry.registerContract{value: 0.01 ether}(address(dummy), 0);

        bytes32 contractHash = registry.getContractHash(address(dummy));
        assert(registry.isRegistered(contractHash));
    }

    function test_registerContract_insufficientBounty() public {
        DummyTarget dummy = new DummyTarget();
        try registry.registerContract{value: 0.001 ether}(address(dummy), 0) {
            revert("Should have reverted");
        } catch {}
    }

    function test_addBounty() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 0.01 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        // Add more bounty
        registry.addBounty{value: 1 ether}(contractHash);

        (, , , uint256 bounty, , , ) = registry.registry(contractHash);
        assert(bounty == 1.01 ether);
    }

    // ── Exploit Claim Tests ──────────────────────────────────────────────

    function test_recordExploit() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        // Set caller as validator
        registry.setValidator(address(this), true);

        // Record exploit
        bytes32 fingerprint = keccak256("exploit-1");
        uint256 severity = 0.5e18; // 50% severity
        registry.recordExploit(contractHash, fingerprint, MINER, severity);

        assert(registry.getExploitCount(contractHash) == 1);
    }

    // ── Deactivation Tests ───────────────────────────────────────────────

    function test_deactivateContract() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 0.01 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        registry.deactivateContract(contractHash);
        assert(!registry.isRegistered(contractHash));
    }

    // ── Expiry Tests ─────────────────────────────────────────────────────────────────

    function test_recordExploit_after_expiry_reverts() public {
        DummyTarget dummy = new DummyTarget();
        uint256 expiry = block.timestamp + 1 hours;
        registry.registerContract{value: 10 ether}(address(dummy), expiry);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        // Warp past expiry
        vm.warp(expiry + 1);

        bytes32 fingerprint = keccak256("exploit-1");
        vm.expectRevert(ProtocolRegistry.ContractExpired.selector);
        registry.recordExploit(contractHash, fingerprint, MINER, 0.5e18);
    }

    function test_recordExploit_before_expiry_succeeds() public {
        DummyTarget dummy = new DummyTarget();
        uint256 expiry = block.timestamp + 1 hours;
        registry.registerContract{value: 10 ether}(address(dummy), expiry);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        // Still within expiry
        vm.warp(expiry - 1);

        bytes32 fingerprint = keccak256("exploit-1");
        registry.recordExploit(contractHash, fingerprint, MINER, 0.5e18);
        assertEq(registry.getExploitCount(contractHash), 1);
    }

    function test_recordExploit_no_expiry_always_succeeds() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        // Warp far into the future
        vm.warp(block.timestamp + 365 days);

        bytes32 fingerprint = keccak256("exploit-1");
        registry.recordExploit(contractHash, fingerprint, MINER, 0.5e18);
        assertEq(registry.getExploitCount(contractHash), 1);
    }

    function test_payExploitReward_after_expiry_succeeds() public {
        // H19 fix: reward is snapshotted at claim time, so payment should
        // succeed even after contract expiry (miners keep earned rewards).
        DummyTarget dummy = new DummyTarget();
        uint256 expiry = block.timestamp + 2 hours;
        registry.registerContract{value: 10 ether}(address(dummy), expiry);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        bytes32 fingerprint = keccak256("exploit-2");
        registry.recordExploit(contractHash, fingerprint, MINER, 0.5e18);

        // Warp past both disclosure window (72h) AND expiry
        vm.warp(block.timestamp + 73 hours);

        // Should succeed — reward was snapshotted at claim time
        registry.payExploitReward(contractHash, fingerprint);
    }

    // ── withdrawBounty Pagination Tests ──────────────────────────────────

    function test_withdrawBounty_invalidStartIndex_reverts() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 1 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        // Deactivate to allow withdrawal
        registry.deactivateContract(contractHash);

        // startIndex beyond history length should revert
        vm.expectRevert(ProtocolRegistry.InvalidStartIndex.selector);
        registry.withdrawBounty(contractHash, 999);
    }

    function test_withdrawBounty_stillActive_reverts() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 1 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        // Contract is still active — should revert with ContractStillActive
        vm.expectRevert(ProtocolRegistry.ContractStillActive.selector);
        registry.withdrawBounty(contractHash, 0);
    }

    // ── Severity Validation Tests ────────────────────────────────────────

    function test_recordExploit_severityExceedsMax_reverts() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        bytes32 fingerprint = keccak256("exploit-severity");
        // severityScore > 1e18 should revert
        vm.expectRevert(ProtocolRegistry.InvalidSeverity.selector);
        registry.recordExploit(contractHash, fingerprint, MINER, 2e18);
    }

    // ── Expiry Validation Tests ──────────────────────────────────────────

    function test_registerContract_pastExpiry_reverts() public {
        DummyTarget dummy = new DummyTarget();
        // Warp to a realistic timestamp first
        vm.warp(1700000000);
        // expiresAt in the past
        uint256 pastExpiry = block.timestamp - 1;
        vm.expectRevert(ProtocolRegistry.InvalidExpiry.selector);
        registry.registerContract{value: 0.01 ether}(
            address(dummy),
            pastExpiry
        );
    }

    function test_registerContract_currentTimestampExpiry_reverts() public {
        DummyTarget dummy = new DummyTarget();
        // expiresAt == block.timestamp (not strictly in the future)
        vm.expectRevert(ProtocolRegistry.InvalidExpiry.selector);
        registry.registerContract{value: 0.01 ether}(
            address(dummy),
            block.timestamp
        );
    }

    // ── Double Deactivation Tests ────────────────────────────────────────

    function test_deactivateContract_twice_reverts() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 0.01 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        // First deactivation succeeds
        registry.deactivateContract(contractHash);

        // Second deactivation reverts
        vm.expectRevert(ProtocolRegistry.ContractNotActive.selector);
        registry.deactivateContract(contractHash);
    }

    function test_recordExploit_maxSeverity_succeeds() public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        bytes32 fingerprint = keccak256("exploit-max-sev");
        // Exactly 1e18 should succeed
        registry.recordExploit(contractHash, fingerprint, MINER, 1e18);
        assertEq(registry.getExploitCount(contractHash), 1);
    }

    // ── withdrawBounty Pagination Bypass Regression ─────────────────────

    function test_withdrawBounty_startAtHistoryLength_reverts() public {
        // Regression: startIndex == history.length must NOT bypass disclosure checks
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        // Record an exploit to create history entries
        bytes32 fp = keccak256("exploit-bypass");
        registry.recordExploit(contractHash, fp, MINER, 0.5e18);

        // Deactivate
        registry.deactivateContract(contractHash);

        // Try to bypass by passing startIndex == history.length (1)
        vm.expectRevert(ProtocolRegistry.InvalidStartIndex.selector);
        registry.withdrawBounty(contractHash, 1);
    }

    function test_withdrawBounty_noClaims_succeeds() public {
        // No claims — should withdraw immediately with startIndex=0
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 1 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        registry.deactivateContract(contractHash);

        uint256 balBefore = address(this).balance;
        registry.withdrawBounty(contractHash, 0);
        assertGt(address(this).balance, balBefore);
    }

    function test_withdrawBounty_noClaims_nonzeroStart_reverts() public {
        // No claims + non-zero startIndex should fail
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 1 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));

        registry.deactivateContract(contractHash);

        vm.expectRevert(ProtocolRegistry.InvalidStartIndex.selector);
        registry.withdrawBounty(contractHash, 1);
    }

    function testFuzz_withdrawBounty_startIndex(uint256 startIndex) public {
        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: 10 ether}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        // Record 3 exploits
        for (uint256 i = 0; i < 3; i++) {
            bytes32 fp = keccak256(abi.encodePacked("fuzz-exploit-", i));
            registry.recordExploit(contractHash, fp, MINER, 0.1e18);
        }

        registry.deactivateContract(contractHash);

        // Warp past disclosure window
        vm.warp(block.timestamp + 73 hours);

        // Valid startIndex: 0, 1, 2; invalid: >= 3
        if (startIndex >= 3) {
            vm.expectRevert(ProtocolRegistry.InvalidStartIndex.selector);
        }
        registry.withdrawBounty(contractHash, startIndex);
    }

    // ── C1 Overflow Fuzz Test ─────────────────────────────────────────────

    /// @notice Fuzz: recordExploit reward calculation never overflows or exceeds pool.
    function testFuzz_recordExploit_noOverflow(uint256 bountyWei, uint256 severity) public {
        // Bound inputs to realistic ranges
        bountyWei = bound(bountyWei, 0.01 ether, 100_000 ether);
        severity = bound(severity, 1, 1e18);

        DummyTarget dummy = new DummyTarget();
        registry.registerContract{value: bountyWei}(address(dummy), 0);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        bytes32 fp = keccak256(abi.encodePacked("fuzz-overflow", bountyWei, severity));

        // Must not revert from overflow
        registry.recordExploit(contractHash, fp, MINER, severity);

        // Reward must not exceed bounty pool
        (,,, uint256 remainingPool,,,) = registry.registry(contractHash);
        assertLe(remainingPool, bountyWei, "Pool should not exceed original bounty");
    }

    receive() external payable {}
}

/// @dev Dummy contract for testing (needs bytecode for extcodehash)
contract DummyTarget {
    uint256 public value;

    function set(uint256 v) external {
        value = v;
    }

    receive() external payable {}
}
