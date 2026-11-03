"""Canonical JSON: sorted keys, no spaces, no NaN. The bytes are those of directional0.core.canonical, which the stack used
to import: the stack needs nothing outside omega_kernel, omega_compute and omega_world (docs/world_computer/REPRODUCE.md)."""
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
