# Key-Vault Integration Runbook

This runbook describes how to store and retrieve the deployer private key
and other sensitive configuration values using external secret managers
instead of plain-text `.env` files.

---

## 1. AWS Secrets Manager

### Store the key

```bash
aws secretsmanager create-secret \
  --name valayr/deployer \
  --secret-string '{"PRIVATE_KEY":"0x…","TRANSFER_DELAY":"86400"}'
```

### Retrieve at deploy time

```bash
SECRET=$(aws secretsmanager get-secret-value \
  --secret-id valayr/deployer --query SecretString --output text)

export PRIVATE_KEY=$(echo "$SECRET" | jq -r .PRIVATE_KEY)
export TRANSFER_DELAY=$(echo "$SECRET" | jq -r .TRANSFER_DELAY)

forge script script/Deploy.s.sol --broadcast --rpc-url "$RPC_URL"
```

### IAM policy (least-privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:valayr/deployer-*"
    }
  ]
}
```

---

## 2. HashiCorp Vault

### Store the key

```bash
vault kv put secret/valayr/deployer \
  PRIVATE_KEY="0x…" \
  TRANSFER_DELAY="86400"
```

### Retrieve at deploy time

```bash
export PRIVATE_KEY=$(vault kv get -field=PRIVATE_KEY secret/valayr/deployer)
export TRANSFER_DELAY=$(vault kv get -field=TRANSFER_DELAY secret/valayr/deployer)

forge script script/Deploy.s.sol --broadcast --rpc-url "$RPC_URL"
```

### Policy (least-privilege)

```hcl
path "secret/data/valayr/deployer" {
  capabilities = ["read"]
}
```

---

## 3. GCP Secret Manager

### Store the key

```bash
printf '0x…' | gcloud secrets create valayr-deployer-pk --data-file=-
printf '86400' | gcloud secrets create valayr-transfer-delay --data-file=-
```

### Retrieve at deploy time

```bash
export PRIVATE_KEY=$(gcloud secrets versions access latest \
  --secret=valayr-deployer-pk)
export TRANSFER_DELAY=$(gcloud secrets versions access latest \
  --secret=valayr-transfer-delay)

forge script script/Deploy.s.sol --broadcast --rpc-url "$RPC_URL"
```

### IAM binding (least-privilege)

```bash
gcloud secrets add-iam-policy-binding valayr-deployer-pk \
  --member="serviceAccount:deployer@PROJECT.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

---

## 4. Rotation Checklist

1. Generate a new deployer key in a hardware wallet or KMS-backed signer.
2. Update the secret in the vault with the new key.
3. Use `transferOwnership` on each contract to the new address.
4. Wait for `TRANSFER_DELAY` to elapse.
5. Call `acceptOwnership` from the new address.
6. Revoke the old key's access in the vault.
7. Verify `owner()` returns the new address on every contract.

## 5. Emergency Procedures

- **Compromised key**: Immediately call `transferOwnership` to a cold-wallet
  address. The `TRANSFER_DELAY` gives a window to detect and front-run
  malicious transfers.
- **Lost vault access**: Restore from vault's backup/replication. Do not store
  plaintext keys anywhere else.
- **Contract pause**: If the key is compromised before transfer completes,
  call `pause()` on pausable contracts to freeze state until the new owner
  takes over.
