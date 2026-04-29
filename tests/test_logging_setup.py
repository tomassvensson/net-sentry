"""Tests for src/logging_setup.py (N — structured JSON logging)."""

import json
import logging

from src.logging_setup import _build_json_formatter, _build_plain_formatter, setup_logging


class TestSetupLogging:
    def test_setup_logging_plain_adds_handler(self) -> None:
        root = logging.getLogger()
        initial_count = len(root.handlers)
        setup_logging(json_enabled=False)
        assert len(root.handlers) >= 1
        # Restore
        root.handlers = root.handlers[:initial_count]

    def test_setup_logging_json_adds_handler(self) -> None:
        root = logging.getLogger()
        initial_count = len(root.handlers)
        setup_logging(json_enabled=True)
        assert len(root.handlers) >= 1
        # Restore
        root.handlers = root.handlers[:initial_count]

    def test_setup_logging_replaces_existing_handlers(self) -> None:
        root = logging.getLogger()
        # Add a dummy extra handler
        dummy = logging.NullHandler()
        root.addHandler(dummy)
        setup_logging(json_enabled=False)
        # After setup, only ONE StreamHandler should exist (the one we added)
        stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
        assert len(stream_handlers) == 1
        # Restore to clean state
        root.handlers.clear()

    def test_setup_logging_sets_level(self) -> None:
        root = logging.getLogger()
        setup_logging(level=logging.DEBUG, json_enabled=False)
        assert root.level == logging.DEBUG
        # Restore
        root.handlers.clear()
        root.setLevel(logging.WARNING)

    def test_setup_logging_json_uses_json_formatter(self) -> None:
        root = logging.getLogger()
        setup_logging(json_enabled=True)
        handler = next(h for h in root.handlers if isinstance(h, logging.StreamHandler))
        # Formatter should be able to format to valid JSON
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello json",
            args=(),
            exc_info=None,
        )
        formatted = handler.formatter.format(record)
        parsed = json.loads(formatted)
        assert "message" in parsed or "msg" in parsed or "hello json" in formatted
        root.handlers.clear()


class TestBuildPlainFormatter:
    def test_returns_formatter(self) -> None:
        fmt = _build_plain_formatter()
        assert isinstance(fmt, logging.Formatter)

    def test_formats_record(self) -> None:
        fmt = _build_plain_formatter()
        record = logging.LogRecord(
            name="myapp",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = fmt.format(record)
        assert "test message" in output
        assert "INFO" in output
        assert "myapp" in output


class TestBuildJsonFormatter:
    def test_returns_formatter(self) -> None:
        fmt = _build_json_formatter()
        assert isinstance(fmt, logging.Formatter)

    def test_formats_as_json(self) -> None:
        fmt = _build_json_formatter()
        record = logging.LogRecord(
            name="myapp",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="something happened",
            args=(),
            exc_info=None,
        )
        output = fmt.format(record)
        parsed = json.loads(output)
        # Either "message" or the raw msg text must be present
        assert parsed.get("message") == "something happened" or "something happened" in output

    def test_level_field_renamed(self) -> None:
        fmt = _build_json_formatter()
        record = logging.LogRecord(
            name="myapp",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="boom",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(fmt.format(record))
        # Confirm renamed level field is present; "levelname" should be absent
        assert "level" in parsed
        assert "levelname" not in parsed

    def test_logger_field_renamed(self) -> None:
        fmt = _build_json_formatter()
        record = logging.LogRecord(
            name="my.logger",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="msg",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(fmt.format(record))
        assert parsed.get("logger") == "my.logger"
        assert "name" not in parsed


class TestJsonLoggingConfig:
    def test_json_logging_default_false(self) -> None:
        from src.config import AppConfig

        cfg = AppConfig()
        assert cfg.json_logging is False

    def test_json_logging_parsed_from_yaml(self, tmp_path) -> None:
        import yaml

        from src.config import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"json_logging": True}), encoding="utf-8")
        cfg = load_config(str(cfg_file))
        assert cfg.json_logging is True

    def test_json_logging_false_from_yaml(self, tmp_path) -> None:
        import yaml

        from src.config import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"json_logging": False}), encoding="utf-8")
        cfg = load_config(str(cfg_file))
        assert cfg.json_logging is False
