"""
Tests for Round 2 additions: deploy pipeline, auto-mine mode,
key rotation utility, Stage 2 templates, adversarial heuristic,
and Ownable2Step contract.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestDeployScript:

    def test_deploy_script_exists(self):
        script = PROJECT_ROOT / "scripts" / "deploy.sh"
        assert script.exists()

    def test_deploy_script_is_executable(self):
        script = PROJECT_ROOT / "scripts" / "deploy.sh"
        assert os.access(script, os.X_OK)

    def test_deploy_script_has_help(self):
        script = PROJECT_ROOT / "scripts" / "deploy.sh"
        result = subprocess.run(
            ["bash", str(script), "--help"],
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0
        assert "network" in result.stdout.lower()

    def test_deployments_dir_exists(self):
        deploy_dir = PROJECT_ROOT / "deployments"
        assert deploy_dir.exists()


class TestMinerAutoMine:

    def test_auto_mode_flag_parsing(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="auto")
        assert neuron.mode == "auto"

    def test_find_auto_exploit_reentrancy(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        exploits_dir = PROJECT_ROOT / "exploits"
        result = neuron._find_auto_exploit("reentrancy", exploits_dir)
        if (exploits_dir / "reentrancy_basic" / "Exploit.sol").exists():
            assert result is not None

    def test_find_auto_exploit_unknown_class(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        exploits_dir = PROJECT_ROOT / "exploits"
        result = neuron._find_auto_exploit("totally-unknown", exploits_dir)
        assert result is None

    def test_adapt_exploit_replaces_name(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        with tempfile.TemporaryDirectory() as tmp:
            vuln_sol = Path(tmp) / "Vulnerable.sol"
            vuln_sol.write_text(
                "pragma solidity ^0.8.28;\ncontract MyTarget {\n}\n"
            )
            task = {"_source_dir": tmp}
            exploit = "contract Vulnerable { }"
            adapted = neuron._adapt_exploit(exploit, task)
            assert "MyTarget" in adapted
            assert "Vulnerable" not in adapted

    def test_adapt_exploit_no_source_dir(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        exploit = "contract Foo { }"
        adapted = neuron._adapt_exploit(exploit, {})
        assert adapted == exploit

    def test_run_auto_with_no_tasks(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="auto")
        neuron.should_exit = True
        with patch.object(neuron.cli.orch, "list_tasks", return_value=[]):
            neuron._run_auto()


class TestKeyRotation:

    def test_module_imports(self):
        from validator.utils.key_rotation import (
            rotate_validator,
            transfer_ownership,
            batch_rotate_validators,
        )
        assert callable(rotate_validator)
        assert callable(transfer_ownership)
        assert callable(batch_rotate_validators)

    def test_cli_entry_point(self):
        result = subprocess.run(
            [sys.executable, "-m", "validator.utils.key_rotation", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd=str(PROJECT_ROOT),
        )
        assert result.returncode == 0
        assert "rotate-validator" in result.stdout
        assert "transfer-ownership" in result.stdout

    def test_find_cast_binary(self):
        try:
            from validator.utils.key_rotation import _find_cast
            cast_bin = _find_cast()
            assert "cast" in cast_bin
        except RuntimeError:
            pytest.skip("Foundry not installed")

    def test_wallet_address(self):
        try:
            from validator.utils.key_rotation import _find_cast, _wallet_address
            cast_bin = _find_cast()
            addr = _wallet_address(
                cast_bin,
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            )
            assert addr.lower() == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        except RuntimeError:
            pytest.skip("Foundry not installed")


class TestStage2Templates:

    EXPECTED_TEMPLATES = [
        "cross_contract_reentrancy.sol",
        "governance_attack.sol",
        "oracle_manipulation.sol",
        "token_bridge.sol",
        "staking_rewards.sol",
    ]

    def test_stage2_templates_exist(self):
        templates_dir = PROJECT_ROOT / "task-generator" / "templates" / "stage2"
        for name in self.EXPECTED_TEMPLATES:
            assert (templates_dir / name).exists(), name

    def test_stage2_multi_contract(self):
        templates_dir = PROJECT_ROOT / "task-generator" / "templates" / "stage2"
        for sol in templates_dir.glob("*.sol"):
            source = sol.read_text()
            assert source.count("\ncontract ") >= 2, sol.name

    def test_stage2_registered(self):
        from task_generator.generate import VULNERABILITY_TEMPLATES
        classes = [
            "cross-reentrancy", "governance-attack",
            "oracle-manipulation", "token-bridge", "staking-exploit",
        ]
        for cls in classes:
            assert cls in VULNERABILITY_TEMPLATES
            templates = VULNERABILITY_TEMPLATES[cls]
            assert isinstance(templates, list)
            assert all("stage2/" in t for t in templates)

    def test_stage2_corpus_generation(self):
        from task_generator.generate import CorpusGenerator
        with tempfile.TemporaryDirectory() as tmp:
            gen = CorpusGenerator(output_dir=Path(tmp))
            pkgs = gen.generate_batch(count_per_class=1, seed=42)
            stage2_classes = {"cross-reentrancy", "governance-attack",
                             "oracle-manipulation", "token-bridge", "staking-exploit"}
            stage2 = [p for p in pkgs if p.vulnerability_class in stage2_classes]
            assert len(stage2) >= 5

    def test_stage2_invariant_specs(self):
        from task_generator.generate import _invariant_for_class
        classes = [
            "cross-reentrancy", "governance-attack",
            "oracle-manipulation", "token-bridge", "staking-exploit",
        ]
        for cls in classes:
            spec = _invariant_for_class(cls)
            assert spec is not None, cls
            assert spec.description
            assert spec.solidity_condition


class TestAdversarialHeuristic:

    def test_heuristic_returns_tuple(self):
        from validator.engine.adversarial import (
            AdversarialEngine, InvariantRecord, ChallengeSubmission,
        )
        engine = AdversarialEngine()
        inv = InvariantRecord(
            invariant_id=1,
            submitter="0xA",
            target_contract_hash="0xhash",
            description="Balance must not decrease",
            solidity_condition="balance >= initialDeposit",
            compiled_check=b"",
            submitted_at=0.0,
        )
        challenge = ChallengeSubmission(
            miner_address="0xB",
            invariant_id=1,
            exploit_source="contract A { receive() external payable {} }",
            target_task_id="0xtest",
        )
        broken, trace = engine._simulate_challenge_heuristic(inv, challenge)
        assert isinstance(broken, bool)
        assert isinstance(trace, str)

    def test_heuristic_empty_exploit(self):
        from validator.engine.adversarial import (
            AdversarialEngine, InvariantRecord, ChallengeSubmission,
        )
        engine = AdversarialEngine()
        inv = InvariantRecord(
            invariant_id=1,
            submitter="0xA",
            target_contract_hash="0xhash",
            description="Supply constant",
            solidity_condition="totalSupply() == 1000",
            compiled_check=b"",
            submitted_at=0.0,
        )
        challenge = ChallengeSubmission(
            miner_address="0xB",
            invariant_id=1,
            exploit_source="",
            target_task_id="0xtest",
        )
        broken, trace = engine._simulate_challenge_heuristic(inv, challenge)
        assert broken is False

    def test_simulation_methods_exist(self):
        from validator.engine.adversarial import AdversarialEngine
        engine = AdversarialEngine()
        for m in [
            "_simulate_challenge", "_simulate_challenge_heuristic",
            "_sim_start_anvil", "_sim_setup_workspace",
            "_generate_invariant_test", "_load_task_source",
            "_sim_deploy_target", "_sim_run_forge_test",
        ]:
            assert hasattr(engine, m), m


class TestOwnable2StepSolidity:

    def test_ownable2step_exists(self):
        sol = PROJECT_ROOT / "contracts" / "src" / "Ownable2Step.sol"
        assert sol.exists()

    def test_ownable2step_functions(self):
        sol = PROJECT_ROOT / "contracts" / "src" / "Ownable2Step.sol"
        source = sol.read_text()
        for fn in ["transferOwnership", "acceptOwnership",
                    "cancelOwnershipTransfer", "pendingOwner", "onlyOwner"]:
            assert fn in source, fn

    def test_ownable2step_errors(self):
        sol = PROJECT_ROOT / "contracts" / "src" / "Ownable2Step.sol"
        source = sol.read_text()
        for err in ["Unauthorized", "ZeroAddress",
                     "TransferNotReady", "NoPendingTransfer"]:
            assert err in source, err

    def test_contracts_inherit_ownable2step(self):
        for name in ["ExploitRegistry.sol", "ProtocolRegistry.sol"]:
            sol = PROJECT_ROOT / "contracts" / "src" / name
            assert "Ownable2Step" in sol.read_text(), name

    def test_stage3_inherits_ownable2step(self):
        sol = PROJECT_ROOT / "contracts" / "src" / "stage3" / "AdversarialMode.sol"
        assert sol.read_text().count("Ownable2Step") >= 2


class TestMinerNeuronLifecycle:

    def test_create_local_neuron(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        assert neuron.mode == "local"
        assert neuron.wallet is None

    def test_create_auto_neuron(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="auto")
        assert neuron.mode == "auto"

    def test_status_local(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        status = neuron.status()
        assert status["mode"] == "local"
        assert "address" in status

    def test_prepare_and_find_exploit(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="local")
        task_id = "0xtest_round2_prep"
        exploit = "contract PrepTest {}"
        neuron.prepare_exploit(task_id, exploit)
        found = neuron._find_prepared_exploit(task_id)
        assert found is not None
        assert found.read_text() == exploit
        found.unlink(missing_ok=True)

    def test_bittensor_fallback_to_local(self):
        from neurons.miner import MinerNeuron
        neuron = MinerNeuron(mode="bittensor")
        assert neuron.mode == "local"


class TestRetrySubprocess:
    """Failure-path tests for validator.utils.retry.retry_subprocess."""

    def test_timeout_raises_after_retries(self):
        from validator.utils.retry import retry_subprocess

        with pytest.raises(subprocess.TimeoutExpired):
            retry_subprocess(
                ["sleep", "60"],
                max_retries=2,
                backoff_base=0.01,
                timeout=1,
            )

    def test_max_retries_exceeded(self):
        from validator.utils.retry import retry_subprocess

        with pytest.raises(RuntimeError, match="exit"):
            retry_subprocess(
                ["python3", "-c", "import sys; sys.exit(1)"],
                max_retries=2,
                backoff_base=0.01,
                timeout=5,
            )

    def test_file_not_found_fails_fast(self):
        from validator.utils.retry import retry_subprocess

        with pytest.raises(FileNotFoundError):
            retry_subprocess(
                ["__nonexistent_binary_xyz__"],
                max_retries=3,
                backoff_base=0.01,
                timeout=5,
            )

    def test_success_on_first_try(self):
        from validator.utils.retry import retry_subprocess

        result = retry_subprocess(
            ["echo", "hello"],
            max_retries=3,
            backoff_base=0.01,
            timeout=5,
        )
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_captures_stderr_on_failure(self):
        from validator.utils.retry import retry_subprocess

        with pytest.raises(RuntimeError, match="boom"):
            retry_subprocess(
                ["python3", "-c", "import sys; sys.stderr.write('boom'); sys.exit(1)"],
                max_retries=1,
                backoff_base=0.01,
                timeout=5,
            )