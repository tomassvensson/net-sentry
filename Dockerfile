ARG PYTHON_IMAGE=python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

FROM ${PYTHON_IMAGE} AS builder

ARG UV_VERSION=0.11.29

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Resolve and install only from the committed universal lock.  --locked makes
# a stale pyproject/lock pair a build failure instead of silently re-resolving.
RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}"

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ src/
RUN uv sync --locked --no-dev --extra postgres --no-editable --no-cache

FROM ${PYTHON_IMAGE}

LABEL maintainer="net-sentry"
LABEL description="Net Sentry - Network Device Visibility Tracker"

WORKDIR /app

# Install only the runtime tools needed by the enabled scanners.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    net-tools \
    iproute2 \
    iputils-ping \
    bluetooth \
    bluez \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV NET_SENTRY_CONTINUOUS=true
ENV NET_SENTRY_SCAN_INTERVAL=60
ENV PATH="/app/.venv/bin:${PATH}"

RUN useradd --create-home --shell /usr/sbin/nologin net-sentry

# Keep build tooling and source code out of the runtime image.
COPY --from=builder /app/.venv /app/.venv

COPY config.yaml.example config.yaml

RUN mkdir -p /app/data && chown -R net-sentry:net-sentry /app/data

USER net-sentry

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).read()" || exit 1

ENTRYPOINT ["net-sentry"]
