"""OpenTelemetry tracing setup for Net Sentry (O).

Call :func:`setup_tracing` once at application startup to configure a
tracer provider.  When ``enabled=False`` (the default) the call is a no-op
and the standard no-op tracer is used so the rest of the codebase never
needs to know whether tracing is active.

Instrumentation
---------------
* FastAPI — automatic HTTP span creation via
  ``opentelemetry-instrumentation-fastapi``.

Exporters supported
-------------------
``"console"``  — pretty-prints spans to stdout, useful for local debugging.
``"otlp"``     — ships spans to an OTLP endpoint (Jaeger, Tempo, Collector…)
               configured via ``OTEL_EXPORTER_OTLP_ENDPOINT`` env var
               (default ``http://localhost:4317``).
``"none"``     — no-op; no spans are exported even when tracing is enabled.

Usage example (config.yaml):

    tracing:
      enabled: true
      service_name: net-sentry
      exporter: console

Environment variables honoured:
    OTEL_SERVICE_NAME          — overrides ``service_name``
    OTEL_EXPORTER_OTLP_ENDPOINT — OTLP gRPC/HTTP endpoint
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

_logger = logging.getLogger(__name__)

# Module-level flag to prevent double-initialisation
_tracing_initialised = False


def setup_tracing(
    enabled: bool = False,
    service_name: str = "net-sentry",
    exporter: str = "console",
) -> None:
    """Configure the OpenTelemetry tracer provider.

    This function is idempotent — calling it multiple times has no
    additional effect after the first successful call.

    Args:
        enabled: Whether to activate tracing.  When ``False`` the function
            returns immediately and the SDK no-op tracer is used.
        service_name: Logical service name embedded in every span.
        exporter: One of ``"console"``, ``"otlp"``, or ``"none"``.
    """
    global _tracing_initialised  # noqa: PLW0603
    if not enabled or _tracing_initialised:
        return

    try:
        _do_setup_tracing(service_name=service_name, exporter=exporter)
        _tracing_initialised = True
    except ImportError as exc:
        _logger.warning("opentelemetry-sdk is not installed; tracing disabled. (%s)", exc)


def _do_setup_tracing(service_name: str, exporter: str) -> None:
    """Internal helper — always imports from opentelemetry (may raise ImportError)."""
    from opentelemetry import trace
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    effective_name = os.environ.get("OTEL_SERVICE_NAME", service_name)
    resource = Resource(attributes={SERVICE_NAME: effective_name})
    provider = TracerProvider(resource=resource)

    span_exporter = _build_exporter(exporter)
    if span_exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(span_exporter))

    trace.set_tracer_provider(provider)
    _logger.info(
        "OpenTelemetry tracing enabled: service=%s, exporter=%s",
        effective_name,
        exporter,
    )


def _build_exporter(exporter: str) -> Any:
    """Return a span exporter instance for the given name.

    Args:
        exporter: Exporter name (``"console"``, ``"otlp"``, or ``"none"``).

    Returns:
        A span exporter instance, or ``None`` for ``"none"``.
    """
    if exporter == "none":
        return None

    if exporter == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        return ConsoleSpanExporter()

    if exporter == "otlp":
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            return OTLPSpanExporter(endpoint=endpoint)
        except ImportError:
            _logger.warning(
                "opentelemetry-exporter-otlp-proto-grpc not installed; falling back to ConsoleSpanExporter."
            )
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter

            return ConsoleSpanExporter()

    _logger.warning("Unknown OTEL exporter %r; no spans will be exported.", exporter)
    return None


def instrument_fastapi(app: FastAPI) -> None:
    """Attach OpenTelemetry automatic instrumentation to a FastAPI app.

    Safe to call even when tracing is disabled — the function is a no-op
    if the instrumentation package is not installed.

    Args:
        app: The FastAPI application instance to instrument.
    """
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
        _logger.debug("FastAPI OpenTelemetry instrumentation attached.")
    except ImportError:
        _logger.debug("opentelemetry-instrumentation-fastapi not installed; skipping.")
