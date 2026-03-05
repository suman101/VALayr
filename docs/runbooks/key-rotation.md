# Validator Key Rotation SOP

## When to Rotate

- Scheduled: every 90 days
- Emergency: immediately if key compromise suspected
- On personnel change: when a validator operator leaves

## Pre-Rotation

1. Generate new key pair:
   ```bash
   cast wallet new
   ```
2. Fund new address with ETH for gas
3. Verify new address: `cast wallet address <new_private_key>`

## Rotation Procedure

1. Register new key as validator on all contracts:
   ```bash
   cast send <ProtocolRegistry> "setValidator(address,bool)" <new_addr> true \
     --rpc-url $RPC_URL --private-key $OLD_KEY
   cast send <ExploitRegistry> "setValidator(address,bool)" <new_addr> true \
     --rpc-url $RPC_URL --private-key $OLD_KEY
   cast send <InvariantRegistry> "setValidator(address,bool)" <new_addr> true \
     --rpc-url $RPC_URL --private-key $OLD_KEY
   cast send <AdversarialScoring> "setValidator(address,bool)" <new_addr> true \
     --rpc-url $RPC_URL --private-key $OLD_KEY
   ```
2. Update validator config with new key
3. Restart validator process
4. Verify new key works (process one submission)
5. Remove old key from all contracts:
   ```bash
   cast send <ProtocolRegistry> "setValidator(address,bool)" <old_addr> false ...
   ```

## Post-Rotation

- [ ] Old key removed from all contracts
- [ ] Old key removed from all config files and env vars
- [ ] Old key securely destroyed or archived
- [ ] Rotation logged in operational log
