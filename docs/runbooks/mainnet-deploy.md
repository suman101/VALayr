# Mainnet Deployment Checklist

> Version 1.2 · Last updated: 2026-03-06

## Pre-Deploy

- [ ] All Foundry tests passing (`forge test`)
- [ ] All Python tests passing (`pytest tests/`)
- [ ] Security scan clean (`pip-audit --strict`, `bandit -r validator/ miner/`)
- [ ] Docker images build and smoke-test
- [ ] `TRANSFER_DELAY` overridden to 48 hours in production subcontracts
- [ ] Multi-sig wallet configured for contract ownership
- [ ] RPC endpoint verified (not using public free endpoint for mainnet)

## Contract Deployment

1. Set env vars: `RPC_URL`, `DEPLOYER_KEY`, `ETHERSCAN_API_KEY`
2. Run: `forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify`
3. Verify all contracts on block explorer
4. Transfer ownership to multi-sig: `cast send <contract> "transferOwnership(address)" <multisig>`
5. Accept ownership from multi-sig wallet
6. Register validators: `cast send <contract> "setValidator(address,bool)" <validator> true`

## Treasury Contract Deployment

1. Deploy Treasury with the validator address:
   ```bash
   forge create contracts/src/Treasury.sol:Treasury \
     --constructor-args $VALIDATOR_ADDRESS \
     --rpc-url $RPC_URL \
     --private-key $DEPLOYER_KEY \
     --verify --etherscan-api-key $ETHERSCAN_API_KEY
   ```
2. Transfer ownership to multi-sig:
   ```bash
   cast send $TREASURY "transferOwnership(address)" $MULTISIG \
     --rpc-url $RPC_URL --private-key $DEPLOYER_KEY
   ```
3. Accept from multi-sig, then verify:
   ```bash
   cast call $TREASURY "owner()" --rpc-url $RPC_URL
   cast call $TREASURY "validator()" --rpc-url $RPC_URL
   ```

## Contract Address Configuration

After deployment, record all contract addresses in `deployments/`:

```bash
# Save deployment manifest
cat > deployments/deploy_mainnet_$(date +%Y%m%d_%H%M%S).json <<EOF
{
  "network": "mainnet",
  "chain_id": 1,
  "deployer": "$DEPLOYER_ADDRESS",
  "contracts": {
    "ProtocolRegistry": "<address>",
    "ExploitRegistry": "<address>",
    "InvariantRegistry": "<address>",
    "AdversarialScoring": "<address>",
    "Treasury": "<address>"
  },
  "multisig": "$MULTISIG",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
```

Set the Treasury address in validator environment:

```bash
export VALAYR_TREASURY_ADDRESS=<Treasury address>
```

## Bittensor Subnet Registration

1. **Register the subnet** (if not already registered):
   ```bash
   btcli subnet create --wallet.name owner --subtensor.network finney
   ```
2. **Note the assigned NETUID** from the output.
3. **Register validator**:
   ```bash
   btcli subnet register --netuid <NETUID> \
     --wallet.name validator --wallet.hotkey default \
     --subtensor.network finney
   ```
4. **Register miners** (each miner runs independently):
   ```bash
   btcli subnet register --netuid <NETUID> \
     --wallet.name miner --wallet.hotkey default \
     --subtensor.network finney
   ```
5. **Verify registration**:
   ```bash
   btcli subnet list --subtensor.network finney
   btcli wallet overview --wallet.name validator --subtensor.network finney
   ```

## Post-Deploy Verification

- [ ] `cast call <ProtocolRegistry> "owner()"` returns multi-sig address
- [ ] `cast call <ExploitRegistry> "owner()"` returns multi-sig address
- [ ] `cast call <Treasury> "owner()"` returns multi-sig address
- [ ] `cast call <Treasury> "validator()"` returns validator address
- [ ] All `validators()` mappings return true for registered validators
- [ ] Validator is registered on Bittensor subnet (`btcli subnet list`)

## Monitoring Setup

- [ ] Prometheus scraping validator metrics endpoint
- [ ] Grafana dashboard imported
- [ ] Alert rules loaded in Prometheus
- [ ] Alertmanager routing configured (Slack/webhook)

## Rollback Plan

- If contracts have a bug: call `pause()` from multi-sig immediately
- Document deployed contract addresses in `deployments/` directory
- Keep deployer key in cold storage after ownership transfer
