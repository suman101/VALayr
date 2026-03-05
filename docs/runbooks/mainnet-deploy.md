# Mainnet Deployment Checklist

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

## Post-Deploy Verification

- [ ] `cast call <ProtocolRegistry> "owner()"` returns multi-sig address
- [ ] `cast call <ExploitRegistry> "owner()"` returns multi-sig address
- [ ] All `validators()` mappings return true for registered validators

## Monitoring Setup

- [ ] Prometheus scraping validator metrics endpoint
- [ ] Grafana dashboard imported
- [ ] Alert rules loaded in Prometheus
- [ ] Alertmanager routing configured (Slack/webhook)

## Rollback Plan

- If contracts have a bug: call `pause()` from multi-sig immediately
- Document deployed contract addresses in `deployments/` directory
- Keep deployer key in cold storage after ownership transfer
