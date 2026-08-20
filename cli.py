"""
Command line interface.

    ffxforensics sample   ./evidence          # build the Case 029 test dataset
    ffxforensics acquire  ~/.mozilla/... ./wd # forensic copy + hashes + archive
    ffxforensics verify   manifest.sha256 ./wd
    ffxforensics info     ./evidence
    ffxforensics analyze  ./evidence -o ./results --tz +01:00
    ffxforensics timeline ./evidence
    ffxforensics search   ./evidence "sql injection"

Exit codes: ``0`` success, ``1`` runtime/evidence error, ``2`` integrity
verification failed, ``130`` interrupted.  Non-zero on integrity failure means
the tool can be dropped into a pipeline that must halt when evidence does not
verify.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from ffxforensics import __version__
from ffxforensics.acquire import acquire_profile
from ffxforensics.analysis.indicators import IndicatorEngine, load_rules
from ffxforensics.audit import AuditTrail
from ffxforensics.case import CaseAnalyser, CaseMetadata
from ffxforensics.hashing import verify_manifest
from ffxforensics.parsers import ArtefactError, PlacesArtefact
from ffxforensics.report.exporters import export_all
from ffxforensics.report.html import write_html
from ffxforensics.report.markdown import write_markdown
from ffxforensics.timeutil import TimezoneError, parse_tz

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY = 2


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ffxforensics",
        description=(
            "Firefox browser artefact forensics toolkit — ACPO-aligned "
            "acquisition, preservation and analysis."
        ),
        epilog="Use this only on systems you are authorised to examine.",
    )
    parser.add_argument("--version", action="version", version=f"ffxforensics {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_case_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--case-id", default="029", help="Case or file number")
        sub.add_argument("--examiner", default="", help="Name of the examiner")
        sub.add_argument("--subject", default="", help="Subject of the examination")
        sub.add_argument("--organisation", default="", help="Employing organisation")
        sub.add_argument("--exhibit", default="", help="Exhibit reference")
        sub.add_argument("--device", default="", help="Device make/model")
        sub.add_argument("--os", dest="operating_system", default="", help="Operating system")
        sub.add_argument("--browser", default="", help="Browser name and version")
        sub.add_argument("--notes", default="", help="Free-text notes for the report header")

    # -- sample ------------------------------------------------------------
    sample = subparsers.add_parser(
        "sample", help="Generate the synthetic Case 029 evidence set for testing"
    )
    sample.add_argument("output", help="Directory to create the profile in")
    sample.add_argument(
        "--tz", default="+01:00", help="Timezone the scenario times are expressed in"
    )

    # -- acquire -----------------------------------------------------------
    acquire = subparsers.add_parser(
        "acquire", help="Create a hashed forensic copy of a Firefox profile"
    )
    acquire.add_argument("profile", help="Path to the Firefox profile directory")
    acquire.add_argument("output", help="Working directory for the evidence copy")
    acquire.add_argument("--name", default="Firefox-Linux-Evidence", help="Evidence set name")
    acquire.add_argument("--no-archive", action="store_true", help="Skip creating the .zip")
    acquire.add_argument(
        "--no-lock", action="store_true", help="Do not chmod the copy to read-only"
    )
    acquire.add_argument("--audit", default="", help="Write the audit trail to this CSV path")
    add_case_options(acquire)

    # -- verify ------------------------------------------------------------
    verify = subparsers.add_parser("verify", help="Verify a directory against a manifest")
    verify.add_argument("manifest", help="Path to a sha256sum-format manifest")
    verify.add_argument("root", help="Directory the manifest paths are relative to")
    verify.add_argument(
        "--strict", action="store_true", help="Also report files missing from the manifest"
    )
    verify.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # -- info --------------------------------------------------------------
    info = subparsers.add_parser("info", help="Inventory artefacts and print hashes")
    info.add_argument("evidence", help="Evidence directory")
    info.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # -- analyze -----------------------------------------------------------
    analyze = subparsers.add_parser("analyze", help="Full analysis and report generation")
    analyze.add_argument("evidence", help="Evidence directory containing the profile")
    analyze.add_argument("-o", "--output", default="results", help="Directory for outputs")
    analyze.add_argument("--tz", default="UTC", help="Timezone for rendered timestamps")
    analyze.add_argument("--rules", default="", help="Custom indicator ruleset (JSON)")
    analyze.add_argument(
        "--manifest", default="", help="Manifest to verify before analysing"
    )
    analyze.add_argument(
        "--session-gap", type=int, default=30, help="Session split gap in minutes"
    )
    analyze.add_argument(
        "--include-cookies-timeline",
        action="store_true",
        help="Include cookie access events in the timeline",
    )
    analyze.add_argument("--no-html", action="store_true", help="Skip the HTML report")
    analyze.add_argument("--quiet", action="store_true", help="Suppress the console summary")
    add_case_options(analyze)

    # -- timeline ----------------------------------------------------------
    timeline = subparsers.add_parser("timeline", help="Print the unified timeline")
    timeline.add_argument("evidence", help="Evidence directory")
    timeline.add_argument("--tz", default="UTC", help="Timezone for rendered timestamps")
    timeline.add_argument("--limit", type=int, default=100, help="Maximum events to print")
    timeline.add_argument(
        "--flagged-only", action="store_true", help="Only show events matching an indicator"
    )

    # -- search ------------------------------------------------------------
    search = subparsers.add_parser("search", help="Keyword search across all artefacts")
    search.add_argument("evidence", help="Evidence directory")
    search.add_argument("term", help="Case-insensitive substring to look for")
    search.add_argument("--tz", default="UTC", help="Timezone for rendered timestamps")

    return parser


def _metadata(args: argparse.Namespace) -> CaseMetadata:
    return CaseMetadata(
        case_id=getattr(args, "case_id", "029"),
        examiner=getattr(args, "examiner", ""),
        subject=getattr(args, "subject", ""),
        organisation=getattr(args, "organisation", ""),
        evidence_name=getattr(args, "name", "Firefox-Linux-Evidence"),
        exhibit_reference=getattr(args, "exhibit", ""),
        device=getattr(args, "device", ""),
        operating_system=getattr(args, "operating_system", ""),
        browser=getattr(args, "browser", ""),
        notes=getattr(args, "notes", ""),
    )


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_sample(args: argparse.Namespace) -> int:
    from ffxforensics.sampledata import build_case_029

    profile = build_case_029(args.output, tz_spec=args.tz)
    print(f"Sample Case 029 profile written to: {profile}")
    print("Analyse it with:")
    print(f"  ffxforensics analyze {profile} -o results --tz {args.tz}")
    return EXIT_OK


def cmd_acquire(args: argparse.Namespace) -> int:
    trail = AuditTrail(case_id=args.case_id, examiner=args.examiner)
    result = acquire_profile(
        args.profile,
        args.output,
        evidence_name=args.name,
        make_archive=not args.no_archive,
        lock_read_only=not args.no_lock,
        trail=trail,
    )
    print(result.summary())
    if args.audit:
        path = trail.to_csv(args.audit)
        print(f"Audit trail       : {path}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_manifest(args.manifest, args.root, strict=args.strict)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(result.summary())
        for name in result.mismatched:
            print(f"  MISMATCH : {name}")
        for name in result.missing:
            print(f"  MISSING  : {name}")
        for name in result.unexpected:
            print(f"  UNEXPECTED: {name}")
    return EXIT_OK if result.ok else EXIT_INTEGRITY


def cmd_info(args: argparse.Namespace) -> int:
    analyser = CaseAnalyser(args.evidence)
    inventory = []
    for label, filename in (
        ("places", "places.sqlite"),
        ("cookies", "cookies.sqlite"),
        ("formhistory", "formhistory.sqlite"),
    ):
        path = analyser.locate(filename)
        if path is None:
            inventory.append({"artefact": label, "status": "absent"})
            continue
        try:
            from ffxforensics.parsers import (
                CookiesArtefact,
                FormHistoryArtefact,
            )

            klass = {
                "places": PlacesArtefact,
                "cookies": CookiesArtefact,
                "formhistory": FormHistoryArtefact,
            }[label]
            with klass(path) as artefact:  # type: ignore[operator]
                entry = artefact.summary()
                entry["status"] = "ok"
                entry["records"] = artefact.statistics()
                inventory.append(entry)
        except ArtefactError as exc:
            inventory.append({"artefact": label, "status": "error", "detail": str(exc)})

    if args.json:
        print(json.dumps(inventory, indent=2))
    else:
        for entry in inventory:
            if entry.get("status") != "ok":
                print(f"{entry['artefact']:<14} {entry.get('status')} "
                      f"{entry.get('detail', '')}")
                continue
            print(f"{entry['artefact']:<14} {entry['file']}")
            print(f"  sha256   : {entry['sha256']}")
            print(f"  size     : {entry['size_bytes']:,} bytes")
            print(f"  integrity: {entry['integrity_check']}")
            print(f"  records  : {entry['records']}")
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    tz = parse_tz(args.tz)
    engine = IndicatorEngine(load_rules(args.rules or None))
    metadata = _metadata(args)
    trail = AuditTrail(case_id=metadata.case_id, examiner=metadata.examiner)

    analyser = CaseAnalyser(
        args.evidence,
        metadata=metadata,
        tz=tz,
        engine=engine,
        trail=trail,
        session_gap_minutes=args.session_gap,
    )

    integrity_failed = False
    if args.manifest:
        verification = verify_manifest(args.manifest, args.evidence)
        trail.record(
            "Evidence Preservation",
            "ffxforensics.hashing",
            command=f"sha256sum -c {Path(args.manifest).name}",
            explanation="Verified the evidence set against its acquisition manifest",
            artefact=str(args.manifest),
            outcome="PASS" if verification.ok else "FAIL",
        )
        integrity_failed = not verification.ok

    result = analyser.run(include_cookies_in_timeline=args.include_cookies_timeline)

    if args.manifest:
        result.integrity = verification.as_dict()  # type: ignore[assignment]

    out_dir = Path(args.output)
    written: List[Path] = export_all(result, out_dir)
    written.append(write_markdown(result, out_dir / "examination_report.md", trail))
    if not args.no_html:
        written.append(write_html(result, out_dir / "examination_report.html", trail))
    written.append(trail.to_csv(out_dir / "audit_trail.csv"))
    written.append(trail.to_json(out_dir / "audit_trail.json"))
    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps(result.summary(), indent=2, default=str), encoding="utf-8"
    )
    written.append(summary_path)

    if not args.quiet:
        summary = result.summary()
        print(f"Case {metadata.case_id} — analysis complete ({result.timezone})")
        for key, value in summary["counts"].items():
            print(f"  {key:<16}: {value}")
        assessment = result.assessment or {}
        print(f"  indicator score : {assessment.get('total_score', 0)} "
              f"({assessment.get('flagged_count', 0)} artefacts flagged, "
              f"highest severity: {assessment.get('highest_severity', 'info')})")
        for error in result.errors:
            print(f"  note            : {error}")
        print(f"\nOutputs written to {out_dir.resolve()}:")
        for path in written:
            print(f"  {Path(path).name}")

    return EXIT_INTEGRITY if integrity_failed else EXIT_OK


def cmd_timeline(args: argparse.Namespace) -> int:
    analyser = CaseAnalyser(args.evidence, tz=parse_tz(args.tz))
    result = analyser.run()
    events = result.timeline
    if args.flagged_only:
        events = [event for event in events if event.indicators]
    for event in events[: args.limit]:
        marker = "!" if event.indicators else " "
        print(
            f"{marker} {event.timestamp_str}  {event.event_type:<28} "
            f"{event.description[:80]}"
        )
    print(f"\n{len(events)} event(s); showing up to {args.limit}.")
    return EXIT_OK


def cmd_search(args: argparse.Namespace) -> int:
    analyser = CaseAnalyser(args.evidence, tz=parse_tz(args.tz))
    result = analyser.run()
    needle = args.term.casefold()
    matches = [
        event
        for event in result.timeline
        if needle in f"{event.description} {event.detail}".casefold()
    ]
    for event in matches:
        print(f"{event.timestamp_str}  {event.source:<20} {event.event_type:<28} "
              f"{event.description[:70]}")
        if event.detail:
            print(f"{'':<22}{event.detail[:100]}")
    print(f"\n{len(matches)} match(es) for {args.term!r}.")
    return EXIT_OK


COMMANDS = {
    "sample": cmd_sample,
    "acquire": cmd_acquire,
    "verify": cmd_verify,
    "info": cmd_info,
    "analyze": cmd_analyze,
    "timeline": cmd_timeline,
    "search": cmd_search,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = COMMANDS[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("Interrupted.", file=sys.stderr)
        return 130
    except (ArtefactError, FileNotFoundError, NotADirectoryError, FileExistsError,
            TimezoneError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
