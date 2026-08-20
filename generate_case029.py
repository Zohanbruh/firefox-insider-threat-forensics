#!/usr/bin/env python3
"""
Standalone builder for the synthetic Case 029 evidence set.

    python sample_data/generate_case029.py ./demo/source --tz +01:00

Equivalent to `ffxforensics sample`, kept as a script so the dataset can be
regenerated without installing the package.

The data is entirely fabricated. The individual, the employer, the domains and
the video identifiers correspond to no real person or system. It exists so the
toolkit can be tested and demonstrated without distributing case material.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ffxforensics.sampledata import build_case_029, dataset_expectations  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="demo/source",
                        help="directory to create the profile in")
    parser.add_argument("--tz", default="+01:00",
                        help="timezone the scenario times are expressed in")
    parser.add_argument("--overwrite", action="store_true",
                        help="replace an existing profile directory")
    args = parser.parse_args()

    profile = build_case_029(args.output, tz_spec=args.tz, overwrite=args.overwrite)
    expected = dataset_expectations()

    print(f"Profile written to {profile}")
    print(f"  files            : {expected['profile_files']}")
    print(f"  distinct URLs    : {expected['distinct_urls']}")
    print(f"  navigation events: {expected['total_visits']}")
    print(f"  visit types      : {expected['visit_type_counts']}")
    print(f"  bookmark rows    : {expected['bookmark_rows']}")
    print(f"  form entries     : {expected['form_entries']}")
    print(f"  cookies          : {expected['cookies']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
