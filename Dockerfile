FROM python:3.13-slim

LABEL maintainer="net-sentry"
LABEL description="Net Sentry - Network Device Visibility Tracker"

WORKDIR /app

# Install system dependencies for network scanning
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    net-tools \
    iproute2 \
    iputils-ping \
    bluetooth \
    bluez \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for better layer caching
COPY pyproject.toml requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ src/
COPY config.yaml.example config.yaml

# Create data directory
RUN mkdir -p src/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV BTWIFI_CONTINUOUS=true
ENV BTWIFI_SCAN_INTERVAL=60

# Run as non-root user
RUN useradd -m -s /bin/bash btwifi
USER btwifi

ENTRYPOINT ["python", "-m", "src.main"]
