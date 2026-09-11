"""Tests for src/tracing.py (O — OpenTelemetry tracing)."""

import logging


class TestSetupTracing:
    def setup_method(self) -> None:
        # Reset the module-level flag before each test so tests are independent.
        import src.tracing as _t

        _t._tracing_initialised = False

    def test_no_op_when_disabled(self) -> None:
        """setup_tracing(enabled=False) must not change the tracer provider."""
        from opentelemetry import trace

        from src.tracing import setup_tracing

        before = trace.get_tracer_provider()
        setup_tracing(enabled=False)
        after = trace.get_tracer_provider()
        assert before is after

    def test_sets_tracer_provider_when_enabled(self) -> None:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from src.tracing import setup_tracing

        setup_tracing(enabled=True, exporter="none", service_name="test-svc")
        provider = trace.get_tracer_provider()
        assert isinstance(provider, TracerProvider)

    def test_idempotent(self) -> None:
        """Calling setup_tracing twice must not raise and should set flag once."""
        import src.tracing as _t
        from src.tracing import setup_tracing

        setup_tracing(enabled=True, exporter="none")
        assert _t._tracing_initialised is True

        # Second call should be a no-op (flag already set)
        setup_tracing(enabled=True, exporter="none")
        assert _t._tracing_initialised is True

    def test_console_exporter_does_not_raise(self) -> None:
        from src.tracing import setup_tracing

        # Should not raise even though console exporter is used
        setup_tracing(enabled=True, exporter="console")

    def test_none_exporter_does_not_raise(self) -> None:
        from src.tracing import setup_tracing

        setup_tracing(enabled=True, exporter="none")

    def test_unknown_exporter_logs_warning(self, caplog) -> None:
        from src.tracing import setup_tracing

        with caplog.at_level(logging.WARNING, logger="src.tracing"):
            setup_tracing(enabled=True, exporter="bogus_exporter")
        assert any("bogus_exporter" in r.message for r in caplog.records)


class TestBuildExporter:
    def test_none_returns_none(self) -> None:
        from src.tracing import _build_exporter

        assert _build_exporter("none") is None

    def test_console_returns_exporter(self) -> None:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        from src.tracing import _build_exporter

        exp = _build_exporter("console")
        assert isinstance(exp, ConsoleSpanExporter)

    def test_unknown_returns_none(self) -> None:
        from src.tracing import _build_exporter

        result = _build_exporter("does_not_exist")
        assert result is None


class TestInstrumentFastAPI:
    def test_instrument_fastapi_does_not_raise(self) -> None:
        """instrument_fastapi should not raise even if already instrumented."""
        from fastapi import FastAPI

        from src.tracing import instrument_fastapi

        tiny_app = FastAPI()
        # Should not raise
        instrument_fastapi(tiny_app)


class TestTracingConfig:
    def test_tracing_config_defaults(self) -> None:
        from src.config import TracingConfig

        cfg = TracingConfig()
        assert cfg.enabled is False
        assert cfg.service_name == "net-sentry"
        assert cfg.exporter == "console"

    def test_app_config_has_tracing(self) -> None:
        from src.config import AppConfig

        cfg = AppConfig()
        assert hasattr(cfg, "tracing")
        assert cfg.tracing.enabled is False

    def test_tracing_parsed_from_yaml(self, tmp_path) -> None:
        import yaml

        from src.config import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            yaml.dump(
                {
                    "tracing": {
                        "enabled": True,
                        "service_name": "my-svc",
                        "exporter": "none",
                    }
                }
            ),
            encoding="utf-8",
        )
        cfg = load_config(str(cfg_file))
        assert cfg.tracing.enabled is True
        assert cfg.tracing.service_name == "my-svc"
        assert cfg.tracing.exporter == "none"
