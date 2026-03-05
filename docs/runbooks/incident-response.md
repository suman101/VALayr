# Incident Response Runbook

## Detection Signals

- **Metrics endpoint down**: Alertmanager fires `MetricsEndpointDown`
- **High rejection rate**: `HighValidationErrorRate` alert (>50% rejections for 15m)
- **High duplicate rate**: `HighDuplicateRate` alert (>80% for 30m) — possible collusion
- **No valid exploits**: `NoValidExploits` for 3+ hours
- **Contract anomaly**: Unexpected on-chain transactions from non-validator addresses

## Severity Levels

| Level       | Criteria                                               | Response Time     |
| ----------- | ------------------------------------------------------ | ----------------- |
| P1 Critical | Key compromise, funds at risk, contract exploit        | Immediate         |
| P2 High     | Validator down, no exploits processing                 | 1 hour            |
| P3 Medium   | High duplicate/rejection rate, performance degradation | 4 hours           |
| P4 Low      | Monitoring gaps, non-critical bugs                     | Next business day |

## P1: Key Compromise / Contract Exploit

1. **Pause all contracts immediately**:
   ```bash
   cast send <ProtocolRegistry> "pause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
   cast send <ExploitRegistry> "pause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
   cast send <InvariantRegistry> "pause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
   cast send <AdversarialScoring> "pause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
   ```
2. Rotate all validator keys (see key-rotation.md)
3. Assess damage: check on-chain exploit claims, review bounty withdrawals
4. If owner key compromised: initiate ownership transfer to backup multi-sig
5. Post-incident: write post-mortem, update threat model

## P2: Validator Down

1. Check validator process: `systemctl status valayr-validator`
2. Check Anvil health: `curl http://localhost:8545 -X POST -d '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}'`
3. Check disk space: `df -h`
4. Review logs: `journalctl -u valayr-validator --since "1 hour ago"`
5. Restart if needed: `systemctl restart valayr-validator`

## P3: High Duplicate/Collusion Rate

1. Review anti-collusion state: `cat data/anticollusion_state.json | python3 -m json.tool`
2. Identify colluding miners from fingerprint DB overlap
3. If confirmed collusion: adjust scoring weights, report to Bittensor governance

## Recovery

After resolving the incident:

1. **Unpause contracts** (if paused):
   ```bash
   cast send <contract> "unpause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
   ```
2. Verify normal operation resumes (metrics flowing, exploits being validated)
3. Write post-mortem within 48 hours
