#!/usr/bin/env python3
"""Check SonarQube quality gate status and metrics via API.

Usage:
    python scripts/check_sonarqube.py --url http://localhost:9000 --project tomassvensson_btwf --token <token>

Environment variables:
    SONAR_HOST_URL: SonarQube server URL (default: http://localhost:9000)
    SONAR_TOKEN: Authentication token
"""

import argparse
import json
import sys
import urllib.request
from base64 import b64encode
from typing import Any


def get_quality_gate_status(base_url: str, project_key: str, token: str) -> dict[str, Any]:
    """Query SonarQube quality gate status.

    Args:
        base_url: SonarQube server URL.
        project_key: Project key in SonarQube.
        token: Authentication token.

    Returns:
        Quality gate status dictionary.
    """
    url = f"{base_url}/api/qualitygates/project_status?projectKey={project_key}"
    auth = b64encode(f"{token}:".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})

    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read())
        return data


def get_measures(base_url: str, project_key: str, token: str, metric_keys: list[str]) -> dict[str, Any]:
    """Query SonarQube measures.

    Args:
        base_url: SonarQube server URL.
        project_key: Project key in SonarQube.
        token: Authentication token.
        metric_keys: List of metric keys to retrieve.

    Returns:
        Measures dictionary.
    """
    metrics = ",".join(metric_keys)
    url = f"{base_url}/api/measures/component?component={project_key}&metricKeys={metrics}"
    auth = b64encode(f"{token}:".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})

    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read())
        return data


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Check SonarQube quality gate and metrics")
    parser.add_argument("--url", default="http://localhost:9000", help="SonarQube server URL")
    parser.add_argument("--project", required=True, help="Project key")
    parser.add_argument("--token", required=True, help="Authentication token")
    args = parser.parse_args()

    try:
        qg_status = get_quality_gate_status(args.url, args.project, args.token)
        project_status = qg_status.get("projectStatus", {})
        status = project_status.get("status", "UNKNOWN")

        print(f"Quality Gate Status: {status}")

        conditions = project_status.get("conditions", [])
        if conditions:
            print("\nConditions:")
            for condition in conditions:
                metric_key = condition.get("metricKey")
                actual = condition.get("actualValue")
                error_threshold = condition.get("errorThreshold")
                cond_status = condition.get("status")
                print(f"  - {metric_key}: {actual} (threshold: {error_threshold}, status: {cond_status})")

        metrics = get_measures(
            args.url,
            args.project,
            args.token,
            ["coverage", "bugs", "vulnerabilities", "code_smells", "security_hotspots"],
        )

        component = metrics.get("component", {})
        measures = component.get("measures", [])

        if measures:
            print("\nMetrics:")
            for measure in measures:
                metric = measure.get("metric")
                value = measure.get("value")
                print(f"  - {metric}: {value}")

        if status != "OK":
            print(f"\nQuality gate failed with status: {status}")
            return 1

        print("\nQuality gate passed!")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
