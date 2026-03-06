"""Tests for validator.utils.logging — get_logger and root configuration."""

import logging

from validator.utils.logging import get_logger


class TestGetLogger:
    def test_returns_logger_instance(self):
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)

    def test_logger_name_nested_under_exploit_subnet(self):
        logger = get_logger("validator.engine.validate")
        assert logger.name == "exploit_subnet.validator.engine.validate"

    def test_root_logger_exists(self):
        root = logging.getLogger("exploit_subnet")
        assert root.handlers  # at least one handler configured

    def test_root_no_propagation(self):
        root = logging.getLogger("exploit_subnet")
        assert root.propagate is False

    def test_logger_can_log_without_error(self):
        logger = get_logger("test.logging")
        # Should not raise
        logger.debug("debug message")
        logger.info("info message")
        logger.warning("warning message")

    def test_deterministic_returns_same_logger(self):
        a = get_logger("test.same")
        b = get_logger("test.same")
        assert a is b
