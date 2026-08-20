"""
Shared fixtures.

The synthetic Case 029 profile is built **once per test session** into a
temporary directory. Building it is cheap (a few hundred milliseconds) but
every test needs it, so session scope keeps the suite fast while still giving
each run a clean tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make `src/` importable without requiring an editable install.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ffxforensics.analysis.indicators import IndicatorEngine  # noqa: E402
from ffxforensics.case import CaseAnalyser, CaseMetadata  # noqa: E402
from ffxforensics.sampledata import build_case_029, dataset_expectations  # noqa: E402
from ffxforensics.timeutil import parse_tz  # noqa: E402

CASE_TZ = "+01:00"


@pytest.fixture(scope="session")
def expectations() -> dict:
    """Ground truth taken from the Case 029 report grids."""
    return dataset_expectations()


@pytest.fixture(scope="session")
def sample_profile(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A generated Firefox profile matching the Case 029 scenario."""
    base = tmp_path_factory.mktemp("case029")
    return build_case_029(base, tz_spec=CASE_TZ)


@pytest.fixture(scope="session")
def places_path(sample_profile: Path) -> Path:
    return sample_profile / "places.sqlite"


@pytest.fixture(scope="session")
def cookies_path(sample_profile: Path) -> Path:
    return sample_profile / "cookies.sqlite"


@pytest.fixture(scope="session")
def formhistory_path(sample_profile: Path) -> Path:
    return sample_profile / "formhistory.sqlite"


@pytest.fixture(scope="session")
def case_tz():
    return parse_tz(CASE_TZ)


@pytest.fixture(scope="session")
def case_result(sample_profile: Path, case_tz):
    """A full analysis run, shared by the reporting and smoke tests."""
    analyser = CaseAnalyser(
        sample_profile,
        metadata=CaseMetadata(
            case_id="029",
            examiner="A. Adhikari",
            subject="Manisha Rao",
            organisation="NeoQuant Finance Limited",
            device="Dell OptiPlex 7090 MT",
            operating_system="Ubuntu GNU/Linux 24.04.1 LTS (64-bit)",
            browser="Firefox ESR 128.13.0 (64-bit)",
        ),
        tz=case_tz,
        engine=IndicatorEngine(),
    )
    return analyser.run()
