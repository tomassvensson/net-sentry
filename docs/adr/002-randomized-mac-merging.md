# ADR 002 — Randomized MAC address merging

**Date:** 2026-07-14
**Status:** Accepted

---

## Context

Modern devices (iOS ≥ 14, Android ≥ 10, Windows 10+) use *per-network randomized MAC addresses* for privacy. Each time a device joins or probes a network it may present a different Layer-2 address, so the same physical device can appear as many distinct rows in the `devices` table.

This makes long-term tracking inaccurate: the device appears to show up and disappear frequently, total visibility statistics are fragmented, and alert thresholds (e.g. "new unknown device") fire repeatedly for the same physical hardware.

---

## Decision

Implement a **heuristic, non-destructive merge** strategy:

1. A device whose MAC has the *locally-administered bit* set (`first_byte & 0x02 != 0`) is considered a candidate for merging.
2. A *canonical anchor* is a device with a globally-administered MAC (stable OUI assignment) of the same `device_type` that has not already been merged away.
3. Confidence levels determine when a merge is suggested:

   | Level  | Signals required                                         |
   |--------|----------------------------------------------------------|
   | `high` | `device_name` + `vendor` match, **no temporal overlap** |
   | `medium` | `device_name` match only (vendor unknown/differs)      |
   | `low`  | `ip_address` **or** `hostname` match only              |

4. Temporal overlap check: if the randomized MAC and the anchor were visible *simultaneously* (any `VisibilityWindow` rows overlap in time), they cannot be the same physical device → confidence is capped at `low`.
5. The merge is **non-destructive**:
   - All `VisibilityWindow` rows for the randomized MAC are re-attributed to the canonical MAC.
   - `Device.merged_into` is set to the canonical MAC (audit trail).
   - The randomized-MAC `Device` row is **not deleted**.
6. `auto_merge_randomized()` defaults to `dry_run=True` and `min_confidence="high"` to prevent accidental bulk merges.

---

## Alternatives considered

### A — Delete the randomized-MAC row

Simple, but irreversible. Loses the MAC-level audit trail and makes rollback impossible.

### B — Merge unconditionally on name match

High false-positive rate on networks with multiple identical devices (e.g. a fleet of company iPhones all named "iPhone"). Rejected.

### C — Use 802.11r/k/v / PMKID to tie MACs together at the RF level

More accurate, but requires low-level frame capture (monitor mode) and is OS/hardware-dependent. Out of scope for this iteration; can be added as a future high-confidence signal.

### D — Ask the user to confirm each merge

Better accuracy but requires a UI workflow. Deferred to a future iteration; the current API already exposes `find_merge_candidates()` results so a review UI can be built on top.

---

## Caveats and known limitations

1. **False positives are possible.** Two identical device models with the same user-assigned name on the same network will be confidently but incorrectly merged.
2. **Device names change.** After a factory reset or rename, the heuristic loses effectiveness.
3. **Hostname ≠ device.** DHCP hostname matches alone are very weak evidence.
4. **This changes historical aggregation.** After a merge, all historical windows appear under the canonical MAC. If per-MAC precision matters, do not run merges.
5. **Vendor randomization.** Devices with randomized MACs also have a randomized OUI, so vendor-only matching is not implemented (only name+vendor combined).

---

## Consequences

- One new DB column: `devices.merged_into` (migration `004_merged_into`).
- New module `src/mac_merge.py` with three public functions.
- New API endpoint `GET /api/v1/devices/{mac}/merge-candidates`.
- 19 new unit tests in `tests/test_mac_merge.py`.
- No automatic merging on scan — must be triggered explicitly via `auto_merge_randomized()` or the API.
