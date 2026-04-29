#!/usr/bin/env python3
"""Download and refresh the IEEE OUI (Organizationally Unique Identifier) database.

This script fetches the official IEEE MA-L (MAC Address Large) CSV file and
saves it to ``src/data/oui.csv``.  The BtWiFi OUI lookup module picks this
file up automatically on next startup, giving up-to-date vendor names.

Usage::

    python scripts/update_oui_db.py [--output PATH]

The script follows the scraping best-practices from the project guidelines:
- At least 1 second between requests to the same host.
- Exponential backoff (up to 120 s) on transient HTTP errors.
- 404 responses are not retried.
- Downloaded data is saved locally so reruns are cheap.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Official IEEE MA-L (OUI) CSV download URL
_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

_DEFAULT_OUTPUT = Path(__file__).parent.parent / "src" / "data" / "oui.csv"

# Retry / back-off settings
_MIN_DELAY_SECONDS = 1.0       # minimum inter-request delay
_MAX_BACKOFF_SECONDS = 120.0   # maximum backoff cap
_MAX_RETRIES = 5               # total attempts (initial + retries)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Download with exponential backoff
# ---------------------------------------------------------------------------

def _download_with_backoff(url: str) -> bytes:
    """Download *url* with exponential backoff.

    Args:
        url: URL to download.

    Returns:
        Raw response bytes.

    Raises:
        SystemExit: After all retries are exhausted or on a permanent error.
    """
    delay = _MIN_DELAY_SECONDS

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            logger.info("Attempt %d/%d: GET %s", attempt, _MAX_RETRIES, url)
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "net-sentry-oui-updater/1.0 (github.com/tomassvensson/net-sentry)"},
            )
            with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
                data: bytes = response.read()
                logger.info("Downloaded %d bytes.", len(data))
                return data

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                logger.error("HTTP 404: resource not found at %s", url)
                sys.exit(1)
            logger.warning("HTTP %d error on attempt %d: %s", exc.code, attempt, exc)

        except urllib.error.URLError as exc:
            logger.warning("URL error on attempt %d: %s", attempt, exc)

        except TimeoutError:
            logger.warning("Request timed out on attempt %d.", attempt)

        if attempt < _MAX_RETRIES:
            logger.info("Waiting %.1f s before retry…", delay)
            time.sleep(delay)
            delay = min(delay * 2, _MAX_BACKOFF_SECONDS)

    logger.error("All %d attempts failed.  Aborting.", _MAX_RETRIES)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CSV validation
# ---------------------------------------------------------------------------

def _validate_oui_csv(data: bytes) -> int:
    """Return the number of non-header lines in the OUI CSV, or 0 on failure."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = [l for l in text.splitlines() if l.strip() and not l.startswith("Registry")]
        return len(lines)
    except Exception as exc:
        logger.warning("Could not parse OUI CSV: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entrypoint for the OUI updater script."""
    parser = argparse.ArgumentParser(description="Update the local IEEE OUI database.")
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Output path for the OUI CSV (default: {_DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("OUI database URL: %s", _OUI_URL)
    logger.info("Output path:      %s", output_path)

    data = _download_with_backoff(_OUI_URL)

    count = _validate_oui_csv(data)
    if count < 1000:
        logger.error(
            "OUI CSV appears incomplete or malformed (%d entries). Aborting write.", count
        )
        sys.exit(1)

    output_path.write_bytes(data)
    logger.info("Saved %d bytes → %s  (%d entries)", len(data), output_path, count)

    # Brief delay as courtesy to the IEEE server
    time.sleep(_MIN_DELAY_SECONDS)

    logger.info("OUI database update complete.")


if __name__ == "__main__":
    main()
