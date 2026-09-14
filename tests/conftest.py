"""Shared fixtures. Builders live in ``helpers`` so tests can import them directly."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The package under test sits one level up. Prepend so a same-named project
# elsewhere on sys.path cannot shadow either it or this test package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import sample_model  # noqa: E402


@pytest.fixture
def model():
    return sample_model()
