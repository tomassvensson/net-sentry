"""Test that the net-sentry CLI entrypoint is installed and responds to --help."""

import subprocess
import sys

import pytest


@pytest.mark.timeout(30)
def test_net_sentry_help_via_module() -> None:
    """net-sentry --help must exit 0 and print usage information."""
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--help"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    # argparse exits with 0 for --help; some custom parsers may exit 0 too
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}. stderr: {result.stderr}"


@pytest.mark.timeout(30)
def test_net_sentry_entrypoint_installed() -> None:
    """net-sentry console_scripts entry is importable."""
    from importlib.metadata import entry_points

    eps = entry_points(group="console_scripts")
    names = [ep.name for ep in eps]
    assert "net-sentry" in names, f"net-sentry not found in console_scripts. Found: {names}"


@pytest.mark.timeout(30)
def test_btwifi_alias_installed() -> None:
    """btwifi backward-compatibility alias must also be present."""
    from importlib.metadata import entry_points

    eps = entry_points(group="console_scripts")
    names = [ep.name for ep in eps]
    assert "btwifi" in names, f"btwifi alias not found in console_scripts. Found: {names}"
