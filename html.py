"""
Self-contained HTML examination report.

Design constraints that drove the styling
-----------------------------------------
* **Offline first.** Forensic workstations are routinely air-gapped, so the
  output embeds all CSS and uses only locally-installed font stacks. No CDN,
  no webfont, no script.
* **Character-exact evidential values.** Hashes, timestamps and URLs are set
  in a monospaced face so a reviewer can compare them glyph by glyph; prose is
  set in a sans face. The distinction is functional, not decorative.
* **Printable.** Case documents get printed and exhibited, so page-break
  behaviour and an ink-light print palette are part of the stylesheet.
"""

from __future__ import annotations

import html as _html
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ffxforensics.audit import AuditTrail
from ffxforensics.case import CaseResult

MAX_TABLE_ROWS = 200

STYLESHEET = """
:root {
  --ink: #12181f;
  --ink-soft: #38424d;
  --muted: #5c6670;
  --paper: #f7f8f7;
  --card: #ffffff;
  --rule: #d7dcd9;
  --rule-strong: #b3bcb7;
  --accent: #1f5f5b;
  --accent-soft: #e6efee;
  --sev-info: #5c6670;
  --sev-low: #3f6f80;
  --sev-medium: #96660f;
  --sev-high: #b04d1a;
  --sev-critical: #91272a;
  --sans: ui-sans-serif, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "DejaVu Sans Mono", Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.55;
  -webkit-text-size-adjust: 100%;
}
.wrap { max-width: 1120px; margin: 0 auto; padding: 32px 24px 96px; }

/* ---- masthead ------------------------------------------------------- */
.masthead { border-top: 3px solid var(--ink); padding-top: 18px; margin-bottom: 28px; }
.eyebrow {
  font-family: var(--mono); font-size: 11px; letter-spacing: .16em;
  text-transform: uppercase; color: var(--muted); margin: 0 0 6px;
}
h1 { font-size: clamp(24px, 4vw, 34px); line-height: 1.15; margin: 0 0 14px; letter-spacing: -.015em; }
.lede { color: var(--ink-soft); max-width: 62ch; margin: 0; }

/* ---- the custody rail: numbered sections on a continuous hairline ---- */
section { position: relative; padding: 26px 0 6px 0; border-top: 1px solid var(--rule); margin-top: 26px; }
section > h2 {
  font-size: 19px; margin: 0 0 4px; letter-spacing: -.01em;
  display: flex; align-items: baseline; gap: 12px;
}
section > h2 .num {
  font-family: var(--mono); font-size: 12px; color: var(--accent);
  border: 1px solid var(--accent); border-radius: 2px; padding: 1px 6px; flex: none;
}
h3 { font-size: 15px; margin: 26px 0 8px; letter-spacing: .01em; }
.note { color: var(--muted); font-size: 13.5px; margin: 4px 0 14px; max-width: 78ch; }

/* ---- key/value + stat cards ----------------------------------------- */
.grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }
.card { background: var(--card); border: 1px solid var(--rule); border-radius: 3px; padding: 12px 14px; }
.card .k { font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
.card .v { font-family: var(--mono); font-size: 18px; margin-top: 4px; word-break: break-word; }
.card .v.small { font-size: 12.5px; line-height: 1.45; }

/* ---- tables ---------------------------------------------------------- */
.tablewrap { overflow-x: auto; border: 1px solid var(--rule); border-radius: 3px; background: var(--card); }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--rule); vertical-align: top; }
th {
  background: #eef1ef; font-size: 11px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--ink-soft); font-weight: 600; white-space: nowrap; position: sticky; top: 0;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:nth-child(even) { background: #fbfcfb; }
td.mono, .mono { font-family: var(--mono); font-size: 12.5px; }
td.url { max-width: 420px; overflow-wrap: anywhere; }
.empty { padding: 14px; color: var(--muted); font-style: italic; }

/* ---- severity chips -------------------------------------------------- */
.chip {
  display: inline-block; font-family: var(--mono); font-size: 10.5px; letter-spacing: .08em;
  text-transform: uppercase; padding: 2px 7px; border-radius: 2px; border: 1px solid currentColor;
  white-space: nowrap;
}
.sev-info { color: var(--sev-info); }
.sev-low { color: var(--sev-low); }
.sev-medium { color: var(--sev-medium); }
.sev-high { color: var(--sev-high); }
.sev-critical { color: var(--sev-critical); background: #fbeced; }

/* ---- verdict block --------------------------------------------------- */
.verdict { border: 1px solid var(--rule-strong); border-left: 4px solid var(--accent); background: var(--card); padding: 16px 18px; border-radius: 3px; }
.verdict .v-title { font-family: var(--mono); font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); }
.verdict p { margin: 8px 0 0; }
.caveat { background: var(--accent-soft); border: 1px solid #cfe0de; border-radius: 3px; padding: 12px 14px; margin-top: 14px; font-size: 13.5px; }
ul.tight { margin: 6px 0 14px; padding-left: 20px; }
ul.tight li { margin-bottom: 5px; }

/* ---- timeline tape --------------------------------------------------- */
.tape { border-left: 2px solid var(--rule-strong); margin: 10px 0 0 6px; padding-left: 0; list-style: none; }
.tape li { position: relative; padding: 7px 0 7px 18px; border-bottom: 1px dotted var(--rule); }
.tape li::before { content: ""; position: absolute; left: -5px; top: 15px; width: 8px; height: 8px; background: var(--rule-strong); border-radius: 50%; }
.tape li.flagged::before { background: var(--sev-high); }
.tape .t { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.tape .d { display: block; }

footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--rule); color: var(--muted); font-size: 12.5px; }
a { color: var(--accent); }

@media (max-width: 620px) {
  .wrap { padding: 20px 14px 60px; }
  th, td { padding: 7px 9px; }
}
@media print {
  body { background: #fff; font-size: 11pt; }
  .wrap { max-width: none; padding: 0; }
  section { break-inside: auto; page-break-inside: auto; }
  h2, h3 { break-after: avoid; }
  tr { break-inside: avoid; }
  th { position: static; background: #eee; }
  .card, .tablewrap, .verdict { break-inside: avoid; }
}
"""


def esc(value: Any) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _flatten(value: Any) -> str:
    """Render list values (e.g. the mismatched-file list) readably."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "none"
    return str(value)


def _cards(pairs: Sequence[Sequence[Any]], small: bool = False) -> str:
    cls = " small" if small else ""
    cells = "".join(
        f'<div class="card"><div class="k">{esc(key)}</div>'
        f'<div class="v{cls}">{esc(value)}</div></div>'
        for key, value in pairs
        if value not in (None, "")
    )
    return f'<div class="grid">{cells}</div>'


def _table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    mono_columns: Sequence[int] = (),
    url_columns: Sequence[int] = (),
    raw_columns: Sequence[int] = (),
) -> str:
    if not rows:
        return '<div class="tablewrap"><div class="empty">No records recovered.</div></div>'
    head = "".join(f"<th>{esc(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            classes = []
            if index in mono_columns:
                classes.append("mono")
            if index in url_columns:
                classes.append("url")
            attr = f' class="{" ".join(classes)}"' if classes else ""
            content = str(cell) if index in raw_columns else esc(cell)
            cells.append(f"<td{attr}>{content}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<div class="tablewrap"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></div>"
    )


def _chip(severity: str) -> str:
    severity = (severity or "info").lower()
    return f'<span class="chip sev-{esc(severity)}">{esc(severity)}</span>'


def _section(number: str, title: str, body: str) -> str:
    return (
        f'<section><h2><span class="num">{esc(number)}</span>{esc(title)}</h2>{body}</section>'
    )


def render_html(
    result: CaseResult,
    trail: Optional[AuditTrail] = None,
    max_rows: int = MAX_TABLE_ROWS,
) -> str:
    """Render the examination report as a single self-contained HTML document."""
    meta = result.metadata
    assessment: Dict[str, Any] = result.assessment or {}
    interp = assessment.get("interpretation", {})
    parts: List[str] = []

    title = f"Case {meta.case_id} — Firefox browser artefact examination"

    # ---------------------------------------------------------- masthead
    parts.append(
        '<div class="masthead">'
        f'<p class="eyebrow">Digital forensics · examination report · '
        f'generated {esc(result.generated_utc)}</p>'
        f"<h1>{esc(title)}</h1>"
        '<p class="lede">Automated analysis of Mozilla Firefox artefacts produced by '
        "<strong>ffxforensics</strong>. Every figure below is derived directly from the "
        "acquired databases and is reproducible with the command shown in the audit trail."
        "</p></div>"
    )

    # ---------------------------------------------------------- 1 context
    context_rows = [
        ["Case / file number", meta.case_id],
        ["Examiner", meta.examiner],
        ["Subject", meta.subject],
        ["Organisation", meta.organisation],
        ["Exhibit reference", meta.exhibit_reference],
        ["Device", meta.device],
        ["Operating system", meta.operating_system],
        ["Browser", meta.browser],
        ["Evidence set", meta.evidence_name],
        ["Timestamps rendered in", result.timezone],
    ]
    body = _cards(context_rows, small=True)
    if meta.notes:
        body += f'<p class="note">{esc(meta.notes)}</p>'
    parts.append(_section("01", "Investigative context", body))

    # -------------------------------------------------------- 2 integrity
    integrity_body = (
        '<p class="note">Artefacts were opened read-only and immutable '
        "(<code>file:…?mode=ro&amp;immutable=1</code>), so no journal or WAL side-file was "
        "created and the acquisition hashes remain valid — ACPO Principles 1 and 2.</p>"
    )
    integrity_body += _table(
        ["Artefact", "Size (bytes)", "SHA-256", "Integrity check"],
        [
            [
                data.get("file", name),
                f"{data.get('size_bytes', 0):,}",
                data.get("sha256", ""),
                data.get("integrity_check", ""),
            ]
            for name, data in result.artefacts.items()
        ],
        mono_columns=(1, 2, 3),
    )
    if result.integrity:
        integrity_body += "<h3>Manifest verification</h3>"
        integrity_body += _table(
            ["Check", "Result"],
            [[key, _flatten(value)] for key, value in result.integrity.items()],
            mono_columns=(1,),
        )
    parts.append(_section("02", "Evidence handled and integrity", integrity_body))

    # --------------------------------------------------------- 3 overview
    counts = result.summary()["counts"]
    window = result.window or {}
    overview = _cards(
        [
            ["URLs in history", counts["places"]],
            ["Navigation events", counts["visits"]],
            ["Search queries", counts["searches"]],
            ["Bookmarks", counts["bookmarks"]],
            ["Typed form values", counts["form_history"]],
            ["Downloads", counts["downloads"]],
            ["Timeline events", counts["timeline_events"]],
            ["Sessions", counts["sessions"]],
        ]
    )
    overview += "<h3>Activity window</h3>"
    overview += _table(
        ["Measure", "Value"],
        [
            ["First recorded event", window.get("first", "n/a")],
            ["Last recorded event", window.get("last", "n/a")],
            ["Span (seconds)", window.get("span_seconds", 0)],
        ],
        mono_columns=(1,),
    )
    if result.sessions:
        overview += _table(
            ["#", "Start", "End", "Duration", "Events", "Flagged"],
            [
                [
                    session.index,
                    session.start.strftime("%Y-%m-%d %H:%M:%S") if session.start else "",
                    session.end.strftime("%Y-%m-%d %H:%M:%S") if session.end else "",
                    session.duration_human,
                    len(session.events),
                    sum(1 for event in session.events if event.indicators),
                ]
                for session in result.sessions
            ],
            mono_columns=(1, 2, 3),
        )
    parts.append(_section("03", "Overview and activity window", overview))

    # --------------------------------------------------------- 4 searches
    searches = _table(
        ["Search query", "Engine", "Last visited"],
        [[item.query, item.engine, item.last_visited_str] for item in result.searches[:max_rows]],
        mono_columns=(2,),
    )
    parts.append(
        _section(
            "04",
            "Search queries recovered from history",
            '<p class="note">Terms reconstructed from search-engine URLs in '
            "<code>moz_places</code>, deduplicated and ordered by first appearance.</p>"
            + searches,
        )
    )

    # ----------------------------------------------------------- 5 videos
    if result.video_visits:
        videos = _table(
            ["Link", "Title", "Most recent activity"],
            [
                [item.url, item.title, item.visit_date_str]
                for item in result.video_visits[:max_rows]
            ],
            mono_columns=(2,),
            url_columns=(0,),
        )
        parts.append(_section("05", "Video platform activity", videos))

    # -------------------------------------------------------- 6 bookmarks
    bookmarks = _table(
        ["Bookmark", "URL", "Folder", "Last modified"],
        [
            [item.title, item.url, item.folder_path, item.last_modified_str]
            for item in result.bookmark_entries[:max_rows]
        ],
        mono_columns=(3,),
        url_columns=(1,),
    )
    parts.append(
        _section(
            "06",
            "Bookmarks",
            '<p class="note">A bookmark is a deliberate act of retention — the user chose to '
            "keep this resource for later.</p>" + bookmarks,
        )
    )

    # ------------------------------------------------------ 7 visit types
    visit_types = _table(
        ["Category", "Meaning", "Web presence count"],
        [[code, data["label"], data["count"]] for code, data in result.visit_types.items()],
        mono_columns=(0, 2),
    )
    parts.append(
        _section(
            "07",
            "Navigation categories",
            '<p class="note">From <code>moz_historyvisits.visit_type</code>. A typed URL '
            "(category 2) carries more evidential weight than a redirect (categories 5 and 6), "
            "because it reflects a deliberate act rather than a server instruction.</p>"
            + visit_types,
        )
    )

    # -------------------------------------------------------- 8 downloads
    if result.downloads:
        downloads = _table(
            ["File", "Source", "Saved to", "Size", "Started"],
            [
                [
                    item.file_name,
                    item.source_url,
                    item.target_path,
                    item.file_size or "",
                    item.started_str,
                ]
                for item in result.downloads
            ],
            mono_columns=(3, 4),
            url_columns=(1, 2),
        )
        parts.append(_section("08", "Downloads", downloads))

    # ------------------------------------------------- 9 form / typed text
    if result.form_history:
        forms = _table(
            ["Field", "Value", "Times used", "Last used"],
            [
                [item.fieldname, item.value, item.times_used, item.last_used_str]
                for item in result.form_history[:max_rows]
            ],
            mono_columns=(0, 2, 3),
        )
        parts.append(
            _section(
                "09",
                "Typed form and search-bar entries",
                '<p class="note"><code>formhistory.sqlite</code> records text physically entered '
                "at the keyboard — the strongest browser-side indicator of authorship.</p>"
                + forms,
            )
        )

    # ------------------------------------------------------ 10 indicators
    triage = _cards(
        [
            ["Weighted score", assessment.get("total_score", 0)],
            ["Rule hits", assessment.get("hit_count", 0)],
            ["Artefacts flagged", assessment.get("flagged_count", 0)],
            ["Highest severity", assessment.get("highest_severity", "info")],
        ]
    )
    rules = assessment.get("rules_triggered", {})
    if rules:
        triage += _table(
            ["Category", "Severity", "Hits", "Example artefact"],
            [
                [name, _chip(data["severity"]), data["count"], (data["examples"] or [""])[0]]
                for name, data in rules.items()
            ],
            mono_columns=(0, 2),
            raw_columns=(1,),
        )
    flagged = assessment.get("flagged_items", [])[:max_rows]
    if flagged:
        triage += "<h3>Highest-scoring artefacts</h3>"
        triage += _table(
            ["Score", "Severity", "Source", "Artefact", "Categories"],
            [
                [
                    item["score"],
                    _chip(item["severity"]),
                    item["source"],
                    item["text"][:130],
                    ", ".join(item["rules"]),
                ]
                for item in flagged
            ],
            mono_columns=(0,),
            raw_columns=(1,),
        )

    corroboration = assessment.get("corroboration", {})
    if corroboration:
        triage += "<h3>Cross-artefact corroboration</h3>"
        triage += (
            f'<p class="note">{corroboration.get("confirmed_typed_count", 0)} search term(s) '
            "appear in both <code>formhistory.sqlite</code> and <code>places.sqlite</code>, "
            "indicating deliberate keyboard entry rather than redirection or auto-suggestion.</p>"
        )
        triage += _table(
            ["Term confirmed as typed"],
            [[term] for term in corroboration.get("typed_and_in_history", [])[:max_rows]],
        )
    parts.append(
        _section(
            "10",
            "Indicator triage",
            '<p class="note">Automated keyword triage. A score measures <em>topic</em>, '
            "never intent.</p>" + triage,
        )
    )

    # ------------------------------------------------------- 11 timeline
    if result.timeline:
        shown = result.timeline[: min(max_rows, 120)]
        items = "".join(
            f'<li class="{"flagged" if event.indicators else ""}">'
            f'<span class="t">{esc(event.timestamp_str)} · {esc(event.event_type)}</span>'
            f'<span class="d">{esc(event.description)}</span>'
            + (
                f'<span class="t">{esc(", ".join(event.indicators))}</span>'
                if event.indicators
                else ""
            )
            + "</li>"
            for event in shown
        )
        note = (
            f'<p class="note">Showing {len(shown)} of {len(result.timeline)} events; '
            "the complete timeline is in <code>timeline.csv</code>.</p>"
        )
        parts.append(_section("11", "Unified timeline", note + f'<ul class="tape">{items}</ul>'))

    # ------------------------------------------------------ 12 conclusion
    conclusion = (
        '<div class="verdict"><div class="v-title">Verdict</div>'
        f'<p>{esc(interp.get("verdict", "INCONCLUSIVE"))}</p></div>'
    )
    if interp.get("supporting_observations"):
        conclusion += "<h3>Observations that narrow the activity</h3><ul class='tight'>"
        conclusion += "".join(f"<li>{esc(line)}</li>" for line in interp["supporting_observations"])
        conclusion += "</ul>"
    if interp.get("innocent_explanations"):
        conclusion += "<h3>Explanations consistent with the same evidence</h3><ul class='tight'>"
        conclusion += "".join(f"<li>{esc(line)}</li>" for line in interp["innocent_explanations"])
        conclusion += "</ul>"
    if interp.get("recommended_corroboration"):
        conclusion += "<h3>Recommended corroborating enquiries</h3><ul class='tight'>"
        conclusion += "".join(
            f"<li>{esc(line)}</li>" for line in interp["recommended_corroboration"]
        )
        conclusion += "</ul>"
    conclusion += f'<div class="caveat">{esc(interp.get("caveat", ""))}</div>'
    conclusion += (
        '<p class="note">Any disciplinary or legal action should follow organisational policy '
        "and further contextual investigation, not this report alone (ACPO Principle 4).</p>"
    )
    if result.errors:
        conclusion += "<h3>Processing notes</h3><ul class='tight'>"
        conclusion += "".join(f"<li>{esc(error)}</li>" for error in result.errors)
        conclusion += "</ul>"
    parts.append(_section("12", "Conclusion and limitations", conclusion))

    # ----------------------------------------------------- 13 audit trail
    if trail is not None and len(trail):
        audit = _table(
            ["#", "Timestamp (UTC)", "Procedure", "Tool / command", "Explanation", "Artefact", "Hash"],
            [
                [
                    entry.seq,
                    entry.timestamp_utc,
                    entry.phase,
                    entry.command or entry.tool,
                    entry.explanation,
                    entry.artefact,
                    entry.hash,
                ]
                for entry in trail
            ],
            mono_columns=(0, 1, 3, 6),
        )
        parts.append(
            _section(
                "13",
                "Audit trail",
                '<p class="note">ACPO Principle 3 — an independent third party should be able to '
                "repeat these processes and reach the same result.</p>" + audit,
            )
        )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{STYLESHEET}</style>
</head>
<body>
<main class="wrap">
{"".join(parts)}
<footer>
Generated by ffxforensics · Association of Chief Police Officers (2012)
<em>ACPO Good Practice Guide for Digital Evidence</em>, 5th edn.
</footer>
</main>
</body>
</html>
"""
    return document


def write_html(
    result: CaseResult,
    path: os.PathLike | str,
    trail: Optional[AuditTrail] = None,
    max_rows: int = MAX_TABLE_ROWS,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, trail, max_rows), encoding="utf-8")
    return path
