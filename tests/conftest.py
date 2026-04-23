"""Hypothesis profile registration for the fuzzing suite.

Three profiles:
    - ``fast``     — smoke test, ~10 examples each. Catches catastrophic regressions.
    - ``ci``       — default. ~75 examples. Balanced speed/coverage.
    - ``thorough`` — ~1000 examples. Run nightly or before release.

Select via either:
    pytest --hypothesis-profile=thorough
    HYPOTHESIS_PROFILE=fast pytest

Per-test ``@settings(max_examples=...)`` still wins if set; fuzz tests here
deliberately omit that so the profile drives them.
"""
from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

_COMMON = {
    "deadline": None,
    "suppress_health_check": [HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
}

settings.register_profile("fast", max_examples=10, **_COMMON)
settings.register_profile("ci", max_examples=75, **_COMMON)
settings.register_profile("thorough", max_examples=10000, **_COMMON)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))