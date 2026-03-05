#!/usr/bin/env bash
# ── VALayr Contract Deployment Pipeline ──────────────────────────────────────
# Deploys all contracts to a target chain, records addresses, and (optionally)
# verifies source on Etherscan-compatible block explorers.
#
# Usage:
#   ./scripts/deploy.sh                         # Deploy to local Anvil
#   ./scripts/deploy.sh --network testnet       # Deploy to Bittensor testnet
#   ./scripts/deploy.sh --network testnet --verify  # Deploy + verify
#
# Environment variables:
#   DEPLOYER_KEY        Private key for deployment (defaults to Anvil[0])
#   RPC_URL             JSON-RPC endpoint (defaults to http://127.0.0.1:8545)
#   ETHERSCAN_API_KEY   API key for source verification
#   DEPLOY_LOG_DIR      Directory for deployment logs (default: deployments/)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"

NETWORK="${NETWORK:-local}"
VERIFY="${VERIFY:-false}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
DEPLOY_LOG_DIR="${DEPLOY_LOG_DIR:-$PROJECT_ROOT/deployments}"
CHAIN_ID=""

# Default Anvil[0] key (public knowledge — Anvil only)
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK="$2"; shift 2 ;;
        --verify)
            VERIFY="true"; shift ;;
        --rpc-url)
            RPC_URL="$2"; shift 2 ;;
        --key)
            DEPLOYER_KEY="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--network local|testnet|mainnet] [--verify] [--rpc-url URL] [--key KEY]"
            exit 0 ;;
        *)
            echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Network presets ──────────────────────────────────────────────────────────
case "$NETWORK" in
    local)
        RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
        CHAIN_ID="31337"
        ;;
    testnet)
        RPC_URL="${RPC_URL:-https://test.finney.opentensor.ai}"
        CHAIN_ID="945"
        ;;
    mainnet)
        echo "ERROR: Mainnet deployment is not yet supported."
        echo "Use testnet for now."
        exit 1
        ;;
    *)
        echo "Unknown network: $NETWORK"
        exit 1
        ;;
esac

# ── Preflight checks ────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            VALayr Contract Deployment Pipeline              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Network:    $NETWORK"
echo "  RPC URL:    $RPC_URL"
echo "  Chain ID:   $CHAIN_ID"
echo "  Verify:     $VERIFY"
echo "  Log Dir:    $DEPLOY_LOG_DIR"
echo ""

# Check foundry
if ! command -v forge &>/dev/null; then
    echo "ERROR: forge not found. Install Foundry: https://book.getfoundry.sh"
    exit 1
fi

if ! command -v cast &>/dev/null; then
    echo "ERROR: cast not found. Install Foundry: https://book.getfoundry.sh"
    exit 1
fi

# Verify RPC is reachable
echo "[*] Checking RPC connectivity..."
CHAIN_RESPONSE=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || echo "FAIL")
if [[ "$CHAIN_RESPONSE" == "FAIL" ]]; then
    echo "ERROR: Cannot reach RPC at $RPC_URL"
    echo "  - For local: start anvil first (anvil)"
    echo "  - For testnet: check your RPC_URL"
    exit 1
fi
echo "  Chain ID from RPC: $CHAIN_RESPONSE"

# Verify deployer balance
DEPLOYER_ADDR=$(cast wallet address "$DEPLOYER_KEY" 2>/dev/null)
BALANCE=$(cast balance "$DEPLOYER_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
echo "  Deployer:   $DEPLOYER_ADDR"
echo "  Balance:    $BALANCE wei"
echo ""

# ── Compile ──────────────────────────────────────────────────────────────────
echo "[*] Compiling contracts..."
cd "$PROJECT_ROOT"
COMPILE_OUT=$(forge build --root "$PROJECT_ROOT" --force 2>&1) || {
    echo "ERROR: Compilation failed!"
    echo "$COMPILE_OUT" | tail -20
    exit 1
}
echo "$COMPILE_OUT" | grep -E "Compil|Solc|success" | head -5
echo "  Compilation successful."
echo ""

# ── Deploy ───────────────────────────────────────────────────────────────────
mkdir -p "$DEPLOY_LOG_DIR"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
DEPLOY_FILE="$DEPLOY_LOG_DIR/deploy_${NETWORK}_${TIMESTAMP}.json"

echo "[*] Running deployment script (forge script)..."
echo ""

FORGE_ARGS=(
    script "$CONTRACTS_DIR/script/Deploy.s.sol"
    --rpc-url "$RPC_URL"
    --broadcast
    -vvv
)

if [[ "$VERIFY" == "true" && -n "${ETHERSCAN_API_KEY:-}" ]]; then
    FORGE_ARGS+=(--verify --etherscan-api-key "$ETHERSCAN_API_KEY")
fi

# Capture output — pass private key via stdin to avoid ps/proc leakage
DEPLOY_OUTPUT=$(echo "$DEPLOYER_KEY" | forge "${FORGE_ARGS[@]}" --private-key-stdin 2>&1)
DEPLOY_EXIT=$?

if [[ $DEPLOY_EXIT -ne 0 ]]; then
    echo "ERROR: Deployment failed!"
    echo "$DEPLOY_OUTPUT" | tail -20
    exit 1
fi

echo "$DEPLOY_OUTPUT" | grep "Deployed\|== Logs ==" | head -10

# ── Parse addresses from output ─────────────────────────────────────────────
echo ""
echo "[*] Parsing deployed addresses..."

# Try JSON broadcast artifacts first (most reliable), fall back to log grep
BROADCAST_JSON="$CONTRACTS_DIR/broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json"

parse_address_json() {
    # Parse from forge broadcast JSON artifacts using jq
    local label="$1"
    local addr=""
    if [[ -f "$BROADCAST_JSON" ]] && command -v jq &>/dev/null; then
        addr=$(jq -r --arg name "$label" \
            '.transactions[] | select(.contractName == $name and .transactionType == "CREATE") | .contractAddress' \
            "$BROADCAST_JSON" 2>/dev/null | head -1)
    fi
    echo "$addr"
}

parse_address_grep() {
    # Fallback: parse from forge log output via grep
    local label="$1"
    local addr
    addr=$(echo "$DEPLOY_OUTPUT" | grep -i "$label" | grep -oE '0x[0-9a-fA-F]{40}' | head -1 || echo "")
    echo "$addr"
}

parse_address() {
    local label="$1"
    local addr
    addr=$(parse_address_json "$label")
    if [[ -z "$addr" || "$addr" == "null" ]]; then
        addr=$(parse_address_grep "$label")
    fi
    echo "$addr"
}

PROTOCOL_REGISTRY=$(parse_address "ProtocolRegistry")
EXPLOIT_REGISTRY=$(parse_address "ExploitRegistry")
INVARIANT_REGISTRY=$(parse_address "InvariantRegistry")
ADVERSARIAL_SCORING=$(parse_address "AdversarialScoring")

echo "  ProtocolRegistry:   ${PROTOCOL_REGISTRY:-NOT FOUND}"
echo "  ExploitRegistry:    ${EXPLOIT_REGISTRY:-NOT FOUND}"
echo "  InvariantRegistry:  ${INVARIANT_REGISTRY:-NOT FOUND}"
echo "  AdversarialScoring: ${ADVERSARIAL_SCORING:-NOT FOUND}"

# ── Post-deployment verification ─────────────────────────────────────────────
echo ""
echo "[*] Verifying deployments..."

verify_contract() {
    local label="$1"
    local addr="$2"
    if [[ -z "$addr" ]]; then
        echo "  ✗ $label — address not found"
        return 1
    fi
    local code
    code=$(cast code "$addr" --rpc-url "$RPC_URL" 2>/dev/null || echo "0x")
    if [[ ${#code} -gt 2 ]]; then
        echo "  ✓ $label at $addr (code: ${#code} chars)"
        return 0
    else
        echo "  ✗ $label at $addr — no code deployed!"
        return 1
    fi
}

VERIFY_OK=true
verify_contract "ProtocolRegistry" "$PROTOCOL_REGISTRY" || VERIFY_OK=false
verify_contract "ExploitRegistry" "$EXPLOIT_REGISTRY" || VERIFY_OK=false
verify_contract "InvariantRegistry" "$INVARIANT_REGISTRY" || VERIFY_OK=false
verify_contract "AdversarialScoring" "$ADVERSARIAL_SCORING" || VERIFY_OK=false

# ── Check wiring (validator permissions set correctly) ──────────────────────
echo ""
echo "[*] Verifying contract wiring..."

check_validator() {
    local label="$1"
    local addr="$2"
    local deployer="$DEPLOYER_ADDR"
    if [[ -z "$addr" ]]; then return 1; fi

    local is_val
    is_val=$(cast call "$addr" "validators(address)(bool)" "$deployer" --rpc-url "$RPC_URL" 2>/dev/null || echo "false")
    if [[ "$is_val" == "true" ]]; then
        echo "  ✓ $label: deployer is validator"
    else
        echo "  ⚠ $label: deployer is NOT validator"
    fi
}

check_validator "ProtocolRegistry" "$PROTOCOL_REGISTRY"
check_validator "ExploitRegistry" "$EXPLOIT_REGISTRY"

# Check AdversarialScoring has InvariantRegistry wired
if [[ -n "$ADVERSARIAL_SCORING" && -n "$INVARIANT_REGISTRY" ]]; then
    WIRED_REG=$(cast call "$ADVERSARIAL_SCORING" "registry()(address)" --rpc-url "$RPC_URL" 2>/dev/null || echo "")
    WIRED_REG_LC=$(echo "$WIRED_REG" | tr '[:upper:]' '[:lower:]')
    INVREG_LC=$(echo "$INVARIANT_REGISTRY" | tr '[:upper:]' '[:lower:]')
    if [[ "$WIRED_REG_LC" == "$INVREG_LC" ]]; then
        echo "  ✓ AdversarialScoring.registry → InvariantRegistry"
    else
        echo "  ✗ AdversarialScoring.registry mismatch! Expected $INVARIANT_REGISTRY got $WIRED_REG"
        VERIFY_OK=false
    fi
fi

# ── Save deployment record ───────────────────────────────────────────────────
echo ""
echo "[*] Writing deployment record..."

cat > "$DEPLOY_FILE" <<EOF
{
  "network": "$NETWORK",
  "chain_id": "$CHAIN_RESPONSE",
  "deployed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "deployer": "$DEPLOYER_ADDR",
  "contracts": {
    "ProtocolRegistry": "${PROTOCOL_REGISTRY:-null}",
    "ExploitRegistry": "${EXPLOIT_REGISTRY:-null}",
    "InvariantRegistry": "${INVARIANT_REGISTRY:-null}",
    "AdversarialScoring": "${ADVERSARIAL_SCORING:-null}"
  },
  "verified": $VERIFY,
  "foundry_version": "$(forge --version | head -1)"
}
EOF

echo "  → $DEPLOY_FILE"

# ── Also write a .env-style file for easy sourcing ───────────────────────────
ENV_FILE="$DEPLOY_LOG_DIR/.env.${NETWORK}"
cat > "$ENV_FILE" <<EOF
# VALayr deployment — ${NETWORK} — $(date -u +"%Y-%m-%d")
PROTOCOL_REGISTRY_ADDRESS=${PROTOCOL_REGISTRY:-}
EXPLOIT_REGISTRY_ADDRESS=${EXPLOIT_REGISTRY:-}
INVARIANT_REGISTRY_ADDRESS=${INVARIANT_REGISTRY:-}
ADVERSARIAL_SCORING_ADDRESS=${ADVERSARIAL_SCORING:-}
RPC_URL=${RPC_URL}
CHAIN_ID=${CHAIN_RESPONSE}
EOF

echo "  → $ENV_FILE  (source this to set env vars)"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
if [[ "$VERIFY_OK" == "true" ]]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ✓ Deployment successful!                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
else
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         ⚠  Deployment completed with warnings               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
fi
echo ""
echo "Next steps:"
echo "  1. Source addresses: source $ENV_FILE"
echo "  2. Run orchestrator: python3 orchestrator.py generate --count 3"
echo "  3. Start validator:  python3 neurons/validator.py --local"
echo "  4. Start miner:      python3 neurons/miner.py --local"
