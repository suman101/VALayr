"""TC-9: Fingerprint DB corruption and recovery tests."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.fingerprint.dedup import FingerprintEngine


class TestFingerprintDBCorruption:
    """Verify the engine handles corrupt/missing DB files gracefully."""

    def test_load_missing_db(self, tmp_path):
        """Engine should start cleanly when DB file doesn't exist."""
        engine = FingerprintEngine(db_path=tmp_path / "missing.json")
        assert engine.get_fingerprint_count("any_task") == 0

    def test_load_corrupt_json(self, tmp_path):
        """Engine should reset to empty DB on corrupt JSON."""
        db_path = tmp_path / "corrupt.json"
        db_path.write_text("{bad json ~~~")
        engine = FingerprintEngine(db_path=db_path)
        assert engine.get_fingerprint_count("any_task") == 0

    def test_load_empty_file(self, tmp_path):
        """Empty file should not crash the engine."""
        db_path = tmp_path / "empty.json"
        db_path.write_text("")
        engine = FingerprintEngine(db_path=db_path)
        assert engine.get_fingerprint_count("any_task") == 0

    def test_load_wrong_type_json(self, tmp_path):
        """A JSON array instead of object should reset gracefully."""
        db_path = tmp_path / "array.json"
        db_path.write_text("[1, 2, 3]")
        engine = FingerprintEngine(db_path=db_path)
        assert engine.get_fingerprint_count("any_task") == 0

    def test_save_and_reload_roundtrip(self, tmp_path):
        """Verify data persists across engine instances."""
        db_path = tmp_path / "roundtrip.json"
        engine1 = FingerprintEngine(db_path=db_path)
        engine1.check_duplicate("task1", "fp_abc", "miner_1")
        engine1.check_duplicate("task1", "fp_xyz", "miner_2")

        # New engine instance should load the saved state
        engine2 = FingerprintEngine(db_path=db_path)
        assert engine2.get_fingerprint_count("task1") == 2

    def test_prune_removes_old_records(self, tmp_path):
        """Pruning should remove records older than the threshold."""
        import time

        db_path = tmp_path / "prune.json"
        engine = FingerprintEngine(db_path=db_path)

        engine.check_duplicate("task1", "fp_old", "miner_old")
        # Manually age the record
        with engine._lock:
            record = engine._db["task1"]["fp_old"]
            record.first_seen_at = time.time() - 60 * 24 * 3600  # 60 days ago
            engine._save_db_unlocked()

        pruned = engine.prune(max_age_seconds=30 * 24 * 3600)
        assert pruned >= 1
        assert engine.get_fingerprint_count("task1") == 0

    def test_concurrent_write_no_corruption(self, tmp_path):
        """Multiple writes should not corrupt the DB."""
        import threading

        db_path = tmp_path / "concurrent.json"
        engine = FingerprintEngine(db_path=db_path)

        errors = []

        def worker(n):
            try:
                for i in range(10):
                    engine.check_duplicate(f"task_{n}", f"fp_{n}_{i}", f"miner_{n}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Verify all writes persisted
        total = sum(engine.get_fingerprint_count(f"task_{i}") for i in range(5))
        assert total == 50

    def test_reset_clears_db(self, tmp_path):
        """reset_db should remove all data and delete the file."""
        db_path = tmp_path / "reset.json"
        engine = FingerprintEngine(db_path=db_path)
        engine.check_duplicate("task1", "fp1", "miner1")
        assert db_path.exists()

        engine.reset_db()
        assert not db_path.exists()
        assert engine.get_fingerprint_count("task1") == 0
