#!/usr/bin/env bash
# ── VALayr Ownership Transfer Script ─────────────────────────────────────────
# Transfers ownership of all deployed contracts to a multi-sig (e.g., Gnosis Safe).
#
# Uses Ownable2Step: current owner initiates, new owner accepts.
# For a multi-sig, the acceptance tx must be signed via the Safe interface.
#
# Usage (step 1 — initiate transfer):
#   ./scripts/transfer-ownership.sh \
#       --deployment deployments/deploy_local_20260303_061132.json \
#       --new-owner 0xMultiSigAddress
#
# Usage (step 2 — accept, from multi-sig):
#   cast send --rpc-url $RPC_URL <contract> "acceptOwnership()" --private-key $NEW_OWNER_KEY
#
# Environment:
#   DEPLOYER_KEY   Private key of current owner (default: Anvil[0])
#   RPC_URL        JSON-RPC endpoint (default: http://127.0.0.1:8545)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

DEPLOYMENT_FILE=""
NEW_OWNER=""

# ── Find cast ────────────────────────────────────────────────────────────────
CAST_BIN=""
for candidate in "cast" "$HOME/.foundry/bin/cast"; do
    if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
        CAST_BIN="$candidate"
        break
    fi
done
if [[ -z "$CAST_BIN" ]]; then
    echo "[!] cast not found. Install Foundry: https://book.getfoundry.sh"
    exit 1
fi

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --deployment) DEPLOYMENT_FILE="$2"; shift 2 ;;
        --new-owner)  NEW_OWNER="$2"; shift 2 ;;
        --rpc-url)    RPC_URL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$DEPLOYMENT_FILE" ]]; then
    echo "[!] --deployment <path-to-json> is required"
    echo "    Example: ./scripts/transfer-ownership.sh --deployment deployments/deploy_local_*.json --new-owner 0x..."
    exit 1
fi

if [[ -z "$NEW_OWNER" ]]; then
    echo "[!] --new-owner <address> is required"
    exit 1
fi

if [[ ! -f "$DEPLOYMENT_FILE" ]]; then
    echo "[!] Deployment file not found: $DEPLOYMENT_FILE"
    exit 1
fi

# ── Extract contract addresses from deployment JSON ──────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "  VALayr — Ownership Transfer"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "  Deployment: $DEPLOYMENT_FILE"
echo "  New owner:  $NEW_OWNER"
echo "  RPC URL:    $RPC_URL"
echo

CONTRACTS=(
    "ProtocolRegistry"
    "ExploitRegistry"
    "InvariantRegistry"
    "AdversarialScoring"
)

# Validate JSON and extract addresses
for name in "${CONTRACTS[@]}"; do
    addr=$(jq -r ".contracts.${name} // empty" "$DEPLOYMENT_FILE" 2>/dev/null)
    if [[ -z "$addr" ]]; then
        echo "[!] Contract '$name' not found in deployment file"
        exit 1
    fi
done

echo "  Contracts to transfer:"
for name in "${CONTRACTS[@]}"; do
    addr=$(jq -r ".contracts.${name}" "$DEPLOYMENT_FILE")
    current_owner=$(ETH_PRIVATE_KEY="$DEPLOYER_KEY" "$CAST_BIN" call --rpc-url "$RPC_URL" "$addr" "owner()(address)" 2>/dev/null || echo "unknown")
    echo "    $name ($addr) — current owner: $current_owner"
done
echo

# ── Confirm ──────────────────────────────────────────────────────────────────
read -r -p "  Proceed with ownership transfer? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "  Aborted."
    exit 0
fi
echo

# ── Transfer ownership (step 1: initiate) for each contract ──────────────────
FAILED=0
for name in "${CONTRACTS[@]}"; do
    addr=$(jq -r ".contracts.${name}" "$DEPLOYMENT_FILE")
    echo "  [$name] Initiating transfer to $NEW_OWNER..."

    if ETH_PRIVATE_KEY="$DEPLOYER_KEY" "$CAST_BIN" send \
        --rpc-url "$RPC_URL" \
        "$addr" \
        "transferOwnership(address)" \
        "$NEW_OWNER" 2>/dev/null; then

        # Verify pendingOwner was set
        pending=$(ETH_PRIVATE_KEY="$DEPLOYER_KEY" "$CAST_BIN" call --rpc-url "$RPC_URL" "$addr" "pendingOwner()(address)" 2>/dev/null || echo "")
        if [[ "${pending,,}" == "${NEW_OWNER,,}" ]]; then
            echo "    ✓ pendingOwner set to $NEW_OWNER"
        else
            echo "    ⚠ pendingOwner mismatch: $pending (expected $NEW_OWNER)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "    ✗ transferOwnership failed!"
        FAILED=$((FAILED + 1))
    fi
done

echo
echo "═══════════════════════════════════════════════════════════════"
if [[ $FAILED -eq 0 ]]; then
    echo "  Step 1 complete: All ${#CONTRACTS[@]} contracts have pendingOwner set."
    echo
    echo "  NEXT STEP: The new owner ($NEW_OWNER) must call acceptOwnership()"
    echo "  on each contract to finalize the transfer."
    echo
    echo "  If using Gnosis Safe, submit these transactions via the Safe UI:"
    for name in "${CONTRACTS[@]}"; do
        addr=$(jq -r ".contracts.${name}" "$DEPLOYMENT_FILE")
        echo "    cast send --rpc-url $RPC_URL $addr \"acceptOwnership()\""
    done
else
    echo "  ⚠ $FAILED transfer(s) failed. Review output above."
fi
echo "═══════════════════════════════════════════════════════════════"
