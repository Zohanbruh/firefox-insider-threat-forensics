"""
Indicator engine — automated *triage*, not automated conclusions.

The engine tags artefacts against a keyword ruleset and produces a weighted
score.  It exists to stop an examiner having to eyeball several thousand URLs,
and to make the reasoning explicit and reviewable: every hit records which
rule fired and on what text.

A deliberate design limit
-------------------------
A score is a measure of **topic**, never of **intent**.  A penetration tester,
a student revising for a security exam and a genuine insider will all light up
the same rules.  :func:`assess` therefore returns evidence and a
recommendation to seek context — it never returns a verdict.  This matches the
Case 029 conclusion, which explicitly declined to infer intent from browsing
topics alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Rule:
    """One indicator category."""

    name: str
    description: str
    weight: int
    severity: str
    keywords: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)

    def compiled(self) -> List[re.Pattern]:
        compiled = [
            re.compile(rf"(?<!\w){re.escape(keyword)}(?!\w)", re.IGNORECASE)
            for keyword in self.keywords
        ]
        compiled += [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]
        return compiled


@dataclass
class Hit:
    """A single rule firing against a single piece of text."""

    rule: str
    severity: str
    weight: int
    matched: str
    text: str
    source: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "weight": self.weight,
            "matched": self.matched,
            "text": self.text,
            "source": self.source,
        }


#: Default ruleset, tuned for the insider-threat / web-application scenario in
#: Case 029.  Override entirely with ``--rules my_rules.json``.
DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "sql_injection",
        "description": "Research into SQL injection techniques and payloads",
        "weight": 5,
        "severity": "high",
        "keywords": [
            "sql injection", "sqli", "sqlmap", "union select", "or 1=1",
            "blind sql", "error based sql", "sql error page", "injection cheat sheet",
        ],
        "patterns": [r"\bsql\s+(injection|error|payload)\b"],
    },
    {
        "name": "api_enumeration",
        "description": "Discovery of API endpoints, routes or internal documentation",
        "weight": 4,
        "severity": "high",
        "keywords": [
            "exposed database endpoints", "api endpoints", "internal api",
            "api docs", "api routes", "swagger", "openapi", "graphql introspection",
            "api parameters", "api vectors", "api security",
        ],
        "patterns": [r"\bapi\b.*\b(endpoint|route|doc|key|token|leak)\w*\b"],
    },
    {
        "name": "control_bypass",
        "description": "Attempts to defeat client-side controls or hidden modes",
        "weight": 5,
        "severity": "critical",
        "keywords": [
            "bypass client-side validation", "force debug mode", "debug mode",
            "modify url parameter", "parameter tampering", "hidden endpoint",
            "authentication bypass", "waf bypass",
        ],
        "patterns": [r"\bbypass\b.*\b(validation|auth|login|filter|waf)\b"],
    },
    {
        "name": "network_recon",
        "description": "Network or infrastructure reconnaissance",
        "weight": 4,
        "severity": "high",
        "keywords": [
            "lan scan", "port scan", "nmap", "firewall penetration testing",
            "internal vulnerabilities", "network scan", "subdomain enumeration",
            "shodan",
        ],
        "patterns": [r"\bscan\w*\b.*\b(internal|network|lan|port)\b"],
    },
    {
        "name": "security_tooling",
        "description": "Use of interception, inspection or probing tools",
        "weight": 3,
        "severity": "medium",
        "keywords": [
            "request inspector", "requestinspector", "burp suite", "urlscan",
            "devtools network", "network inspector", "inspect network activity",
            "postman", "curl request", "http request probe", "webhook.site",
        ],
    },
    {
        "name": "vulnerability_research",
        "description": "General vulnerability and exploitation study material",
        "weight": 2,
        "severity": "medium",
        "keywords": [
            "owasp", "cve-", "exploit", "vulnerability", "vulnerabilities",
            "threats vulnerabilities and exploits", "penetration testing", "pentest",
            "cheat sheet", "attack surface",
        ],
    },
    {
        "name": "target_organisation",
        "description": "Activity directed at the employing organisation itself",
        "weight": 5,
        "severity": "critical",
        "keywords": ["neoquant", "neo quant", "neoquant finance"],
    },
    {
        "name": "competitor_research",
        "description": "Competitive intelligence or market-position research",
        "weight": 2,
        "severity": "low",
        "keywords": [
            "competitive analysis", "similarweb", "competitor", "market share",
            "white papers",
        ],
    },
    {
        "name": "data_exfiltration",
        "description": "Channels commonly used to move data out of an estate",
        "weight": 5,
        "severity": "critical",
        "keywords": [
            "pastebin", "anonfiles", "mega.nz", "wetransfer", "file.io",
            "tempmail", "protonmail drive", "usb data transfer",
        ],
    },
    {
        "name": "anti_forensics",
        "description": "Interest in destroying or hiding traces of activity",
        "weight": 5,
        "severity": "critical",
        "keywords": [
            "clear browser history", "anti-forensics", "wipe disk",
            "delete places.sqlite", "ccleaner", "secure erase", "log tampering",
        ],
    },
]


def load_rules(path: Optional[Path | str] = None) -> List[Rule]:
    """Load rules from JSON, or return the built-in default ruleset."""
    raw: Sequence[Dict[str, Any]]
    if path:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(raw, dict):  # allow {"rules": [...]} wrapper
            raw = raw.get("rules", [])
    else:
        raw = DEFAULT_RULES
    return [
        Rule(
            name=item["name"],
            description=item.get("description", ""),
            weight=int(item.get("weight", 1)),
            severity=item.get("severity", "info"),
            keywords=list(item.get("keywords", [])),
            patterns=list(item.get("patterns", [])),
        )
        for item in raw
    ]


class IndicatorEngine:
    """Applies a ruleset to arbitrary artefact text."""

    def __init__(self, rules: Optional[Sequence[Rule]] = None) -> None:
        self.rules: List[Rule] = list(rules) if rules is not None else load_rules()
        self._compiled = {rule.name: rule.compiled() for rule in self.rules}

    # -- matching --------------------------------------------------------
    def match(self, text: str, source: str = "") -> List[Hit]:
        """Return every rule hit in ``text`` (one hit per rule, first match)."""
        if not text:
            return []
        hits: List[Hit] = []
        for rule in self.rules:
            for pattern in self._compiled[rule.name]:
                found = pattern.search(text)
                if found:
                    hits.append(
                        Hit(
                            rule=rule.name,
                            severity=rule.severity,
                            weight=rule.weight,
                            matched=found.group(0),
                            text=text,
                            source=source,
                        )
                    )
                    break
        return hits

    def score(self, text: str) -> int:
        """Summed weight of the rules matching ``text``."""
        return sum(hit.weight for hit in self.match(text))

    def categories(self, text: str) -> List[str]:
        return [hit.rule for hit in self.match(text)]

    # -- aggregation -----------------------------------------------------
    def assess(self, items: Iterable[tuple]) -> Dict[str, Any]:
        """Score an iterable of ``(text, source)`` pairs.

        Returns a dictionary containing per-rule counts, the highest severity
        observed, the flagged items, and an explicitly non-conclusive
        interpretation block.
        """
        all_hits: List[Hit] = []
        flagged: List[Dict[str, Any]] = []

        for text, source in items:
            hits = self.match(text, source)
            if not hits:
                continue
            all_hits.extend(hits)
            flagged.append(
                {
                    "text": text,
                    "source": source,
                    "score": sum(hit.weight for hit in hits),
                    "rules": [hit.rule for hit in hits],
                    "severity": max(
                        (hit.severity for hit in hits),
                        key=lambda sev: SEVERITY_ORDER.get(sev, 0),
                    ),
                }
            )

        by_rule: Dict[str, Dict[str, Any]] = {}
        for hit in all_hits:
            bucket = by_rule.setdefault(
                hit.rule,
                {"count": 0, "severity": hit.severity, "weight": hit.weight,
                 "examples": []},
            )
            bucket["count"] += 1
            if len(bucket["examples"]) < 5 and hit.text not in bucket["examples"]:
                bucket["examples"].append(hit.text)

        highest = "info"
        for hit in all_hits:
            if SEVERITY_ORDER.get(hit.severity, 0) > SEVERITY_ORDER.get(highest, 0):
                highest = hit.severity

        flagged.sort(key=lambda item: item["score"], reverse=True)

        return {
            "total_score": sum(hit.weight for hit in all_hits),
            "hit_count": len(all_hits),
            "flagged_count": len(flagged),
            "highest_severity": highest,
            "rules_triggered": dict(
                sorted(by_rule.items(), key=lambda kv: kv[1]["count"], reverse=True)
            ),
            "flagged_items": flagged,
            "interpretation": interpretation(by_rule, highest),
        }


def interpretation(by_rule: Dict[str, Dict[str, Any]], highest: str) -> Dict[str, Any]:
    """Build the non-conclusive interpretation block.

    The wording here is intentionally conservative.  Browsing topics establish
    *what was researched*; they do not establish *why*.  Anything stronger
    requires corroboration the browser cannot provide (proxy logs, application
    logs, DLP, HR context) — the position taken in the Case 029 conclusion.
    """
    triggered = sorted(by_rule)
    supports = []
    alternatives = [
        "Authorised security testing, training or professional development.",
        "Curiosity following a security bulletin, incident or internal announcement.",
        "Job-related research by a developer, QA engineer or analyst.",
    ]

    if "target_organisation" in triggered and (
        "sql_injection" in triggered or "api_enumeration" in triggered
    ):
        supports.append(
            "Security-testing research appears alongside searches naming the "
            "employing organisation, which narrows the activity from generic "
            "study toward a specific estate."
        )
    if "control_bypass" in triggered:
        supports.append(
            "Queries about defeating client-side controls have a narrower "
            "legitimate use than general vulnerability reading."
        )
    if "anti_forensics" in triggered:
        supports.append(
            "Interest in removing traces of activity is difficult to explain "
            "by professional development alone."
        )
    if "data_exfiltration" in triggered:
        supports.append(
            "Known data-transfer channels were researched or visited."
        )

    return {
        "verdict": "INCONCLUSIVE — intent cannot be established from browser artefacts alone",
        "highest_severity": highest,
        "categories_observed": triggered,
        "supporting_observations": supports,
        "innocent_explanations": alternatives,
        "recommended_corroboration": [
            "Proxy / egress logs for the same window, to show whether the "
            "techniques researched were actually attempted.",
            "Web-application and database logs for the named target systems.",
            "The employee's role, current tickets and any authorisation to test.",
            "Endpoint artefacts (shell history, installed tooling) outside the browser.",
            "DLP and email/removable-media logs for any data movement.",
        ],
        "caveat": (
            "Presence of a search term proves the term was submitted from this "
            "profile; it does not prove who submitted it, nor that any action "
            "followed. Attribute to a person only with session, authentication "
            "or physical-access evidence."
        ),
    }
