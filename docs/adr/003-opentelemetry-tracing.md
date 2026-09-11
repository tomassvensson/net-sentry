# ADR 003 — OpenTelemetry tracing as an optional dependency

**Date:** 2025-07-17
**Status:** Accepted

---

## Context

Net Sentry runs on resource-constrained hardware (Raspberry Pi, embedded Linux) as
well as developer laptops and full-stack Docker deployments. Not every deployment
needs distributed tracing, and the OpenTelemetry OTLP exporter dependencies
(`opentelemetry-exporter-otlp-proto-grpc` and its gRPC/protobuf stack) add
significant install size (~15 MB of compiled wheels).

The project already ships `opentelemetry-sdk` as a core dependency because the
`tracer = trace.get_tracer(__name__)` call is cheap when no exporter is configured.
The question is whether to also mandate the OTLP exporter for all users.

---

## Decision

1. Keep `opentelemetry-sdk` and `opentelemetry-instrumentation-fastapi` in the
   **core** dependency list so that trace spans are always available even when no
   exporter is configured (they are silently dropped by the `NoOpTracer`).

2. Ship `opentelemetry-exporter-otlp-proto-grpc` as an **optional
   `[observability]` extra** in `pyproject.toml`:

   ```toml
   [project.optional-dependencies]
   observability = [
       "opentelemetry-exporter-otlp-proto-grpc>=1.20",
   ]
   ```

   Users who want to send traces to an OpenTelemetry Collector install with:

   ```bash
   pip install "net-sentry[observability]"
   ```

3. `src/tracing.py` uses a **graceful `ImportError` fallback**: if the OTLP
   package is absent and the configured exporter is `"otlp"`, it falls back to
   `ConsoleSpanExporter` and logs a warning, so the application never crashes on
   startup due to a missing optional dependency.

4. The console exporter is the default (`tracing.exporter: "console"`); users
   must opt in to OTLP export by setting `tracing.exporter: "otlp"` in
   `config.yaml`.

---

## Alternatives considered

### A — Bundle OTLP exporter as a core dependency

Simple install, but adds ~15 MB of gRPC/protobuf wheels to every deployment,
including minimal Raspberry Pi installs and Docker images where image size
matters. Rejected in favour of the optional-extra approach.

### B — Remove all OpenTelemetry from core, make everything optional

Would prevent any tracing instrumentation unless the extra is installed. The
`opentelemetry-sdk` alone is lightweight (~1 MB) and its `NoOpTracer` adds zero
overhead, so keeping it in core is acceptable and enables future callers to
instrument code without requiring users to install extras.

### C — Use a different tracing backend (e.g. Zipkin, Jaeger-native)

The OpenTelemetry ecosystem is vendor-neutral and the OTLP protocol is supported
by all major observability platforms (Jaeger, Zipkin, Grafana Tempo, Honeycomb,
Datadog). Choosing OTel avoids lock-in and is the current industry standard.

### D — Ship a Docker Compose profile with an OTEL Collector

A `docker-compose.observability.yml` profile is a natural next step (and is
documented in the README as a future improvement) but is out of scope for this
ADR, which focuses only on the Python dependency model.

---

## Trade-offs

| Concern | Impact |
|---------|--------|
| Install size (minimal) | Reduced: core only includes lightweight SDK |
| Developer experience | Slightly more complex: must know to install `[observability]` |
| Startup robustness | High: graceful fallback prevents crashes |
| Observability coverage | Full: all scanner calls and HTTP requests emit spans when enabled |

---

## Consequences

- `src/tracing.py` must guard all `OTLPSpanExporter` imports with `try/except ImportError`.
- CI test dependencies include the SDK (`opentelemetry-sdk` already in `[dev]`).
- The `[observability]` extra is documented in `README.md` and `config.yaml.example`.
- Future work: add a `docker-compose.observability.yml` that brings up an
  OpenTelemetry Collector and a Grafana Tempo backend.
