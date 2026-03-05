// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/ProtocolRegistry.sol";
import "../src/ExploitRegistry.sol";
import "../src/stage3/AdversarialMode.sol";
import "../src/Treasury.sol";

/// @title Deploy — Foundry deployment script for all subnet contracts.
/// @dev Run: forge script contracts/script/Deploy.s.sol --rpc-url <RPC> --broadcast
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", uint256(0));
        if (deployerKey == 0) {
            // Default Anvil deterministic key
            deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        }
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // Deploy ProtocolRegistry
        ProtocolRegistry registry = new ProtocolRegistry();

        // Deploy ExploitRegistry
        ExploitRegistry exploitRegistry = new ExploitRegistry();

        // Deploy Stage 3: AdversarialMode (InvariantRegistry + AdversarialScoring)
        InvariantRegistry invariantRegistry = new InvariantRegistry();
        AdversarialScoring adversarialScoring = new AdversarialScoring(
            address(invariantRegistry)
        );

        // Wire up: set deployer as validator on all registries
        registry.setValidator(deployer, true);
        exploitRegistry.setValidator(deployer, true);
        invariantRegistry.setValidator(deployer, true);
        adversarialScoring.setValidator(deployer, true);

        // Deploy Treasury (winner-takes-all competitions)
        Treasury treasury = new Treasury(deployer);

        vm.stopBroadcast();

        // Log deployed addresses
        console.log("=== Deployed Addresses ===");
        console.log("ProtocolRegistry:   ", address(registry));
        console.log("ExploitRegistry:    ", address(exploitRegistry));
        console.log("InvariantRegistry:  ", address(invariantRegistry));
        console.log("AdversarialScoring: ", address(adversarialScoring));
        console.log("Treasury:           ", address(treasury));
        console.log("Deployer/Validator: ", deployer);
    }
}
