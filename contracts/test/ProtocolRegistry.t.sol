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

    function test_payExploitReward_after_expiry_reverts() public {
        DummyTarget dummy = new DummyTarget();
        uint256 expiry = block.timestamp + 2 hours;
        registry.registerContract{value: 10 ether}(address(dummy), expiry);
        bytes32 contractHash = registry.getContractHash(address(dummy));
        registry.setValidator(address(this), true);

        bytes32 fingerprint = keccak256("exploit-2");
        registry.recordExploit(contractHash, fingerprint, MINER, 0.5e18);

        // Warp past both disclosure window AND expiry
        vm.warp(expiry + 1);

        vm.expectRevert(ProtocolRegistry.ContractExpired.selector);
        registry.payExploitReward(contractHash, fingerprint);
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
