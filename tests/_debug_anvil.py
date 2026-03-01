#!/usr/bin/env python3
"""Quick debug script to test Anvil startup."""
import os, subprocess, json, time, urllib.request
from pathlib import Path

foundry_bin = Path.home() / ".foundry" / "bin"
os.environ["PATH"] = str(foundry_bin) + ":" + os.environ.get("PATH", "")

cmd = [
    "anvil",
    "--host", "127.0.0.1",
    "--port", "28545",
    "--timestamp", "1700000000",
    "--block-base-fee-per-gas", "0",
    "--gas-limit", "30000000",
    "--chain-id", "31337",
    "--accounts", "10",
    "--balance", "10000",
    "--mnemonic", "test test test test test test test test test test test junk",
    "--hardfork", "cancun",
    "--quiet",
]
print("Starting Anvil...")
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
for i in range(30):
    time.sleep(0.2)
    try:
        payload = json.dumps({"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}).encode()
        req = urllib.request.Request("http://127.0.0.1:28545", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if "result" in data:
                print(f"Ready after {(i+1)*0.2:.1f}s: {data}")
                proc.terminate()
                exit(0)
    except Exception as e:
        if i == 29:
            print(f"Never ready: {e}")
            poll = proc.poll()
            if poll is not None:
                print("stderr:", proc.stderr.read().decode())
            proc.terminate()
            exit(1)
