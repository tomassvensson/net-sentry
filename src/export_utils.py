"""Safe serialization helpers for data exported to spreadsheet formats."""

from typing import Any


def sanitize_csv_value(value: Any) -> Any:
    """Prevent user/device-controlled strings from becoming spreadsheet formulas."""
    if not isinstance(value, str):
        return value
    candidate = value.lstrip()
    if candidate.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value
