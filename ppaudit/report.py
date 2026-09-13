"""Findings model and report rendering (console, JSON, HTML).

The three analysis stages all emit :class:`Finding` objects into a
:class:`Report`. Rendering is separated from collection so the same run can be
printed to a terminal, saved as JSON for diffing across audits, and turned into
a shareable HTML page.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Finding:
    """One observation about the target's exposure."""

    severity: Severity
    title: str
    table: str = ""
    detail: str = ""
    # Where this came from: "anon-odata", "anon-api", "dataverse", "correlation".
    source: str = ""
    # Free-form structured evidence (columns exposed, permission ids, counts...).
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class Report:
    target: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    # Raw context the stages want to preserve (discovered schema, role list...).
    context: dict[str, Any] = field(default_factory=dict)
    # Populated by the Dataverse audit: the typed configuration model per
    # generation, and the flattened role-to-table access matrix built from it.
    # The markdown renderer walks these to produce the review document.
    models: list[Any] = field(default_factory=list)
    access_matrix: list[Any] = field(default_factory=list)
    # table -> where the site's Liquid/FetchXML/page scripts reference it.
    references: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.table, f.title))

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    # --- renderers -----------------------------------------------------------

    def to_markdown(self) -> str:
        from . import markdown  # local import: markdown imports this module

        return markdown.render(self)

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "started": self.started,
                "counts": self.counts(),
                "findings": [f.to_dict() for f in self.sorted()],
                "context": self.context,
            },
            indent=2,
            default=str,
        )

    def to_console(self, color: bool = True) -> str:
        ansi = {
            Severity.CRITICAL: "\033[97;41m",
            Severity.HIGH: "\033[91m",
            Severity.MEDIUM: "\033[93m",
            Severity.LOW: "\033[94m",
            Severity.INFO: "\033[90m",
        }
        reset = "\033[0m"
        lines = [f"\nPower Pages exposure audit — {self.target}", "=" * 72]
        counts = self.counts()
        summary = "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
        lines.append(summary or "no findings")
        lines.append("")
        for f in self.sorted():
            tag = f"[{f.severity.label.upper()}]"
            if color:
                tag = f"{ansi[f.severity]}{tag}{reset}"
            where = f" ({f.table})" if f.table else ""
            lines.append(f"{tag} {f.title}{where}")
            if f.detail:
                for row in f.detail.splitlines():
                    lines.append(f"      {row}")
            if f.evidence:
                ev = ", ".join(f"{k}={v}" for k, v in f.evidence.items())
                lines.append(f"      · {ev}")
        return "\n".join(lines)

    def to_html(self) -> str:
        from . import htmlreport  # local import: htmlreport imports this module

        return htmlreport.render(self)
