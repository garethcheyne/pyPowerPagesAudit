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

    @property
    def subject(self) -> str:
        """What this finding is *about*, for a one-line summary.

        Most findings name a table, but the ones that do not — a site setting, a
        web role, a form — then render as several identical lines with no way to
        tell them apart, and the reader has to open each. The evidence already
        holds the answer; a setting also carries its value, since the value is
        the whole reason the finding exists.
        """
        if self.table:
            return self.table
        ev = self.evidence
        setting = str(ev.get("setting") or "")
        if setting:
            value = str(ev.get("value") or "")
            return f"{setting} = {value}" if value else setting
        for key in ("role", "profile", "permission", "form", "page", "generations"):
            if ev.get(key):
                return str(ev[key])
        return ""

    @property
    def qualifiers(self) -> list[str]:
        """What limits (or confirms) this finding, in a few words.

        A severity alone flattens two very different situations: a table a
        visitor can query at will over ``/_api``, and the same permission behind
        a filtered server-side query with no API channel. The severity model
        already accounts for that, but a summary line that omits it invites the
        reader to re-derive it from the detail — or to panic. These are read off
        the evidence the analysers already record, so no renderer has to know
        how a finding was graded.
        """
        ev = self.evidence
        out: list[str] = []
        channel = str(ev.get("channel", ""))

        # An analyser that already knows the consequence says so itself, and it
        # leads: for findings that share a title it is the only thing on the line
        # that explains why this one is here.
        if ev.get("impact"):
            out.append(str(ev["impact"]))

        # Correlation findings exist only because the scanner already read the
        # table from the internet, so they are observations, not inferences.
        if self.source.startswith(("anon", "correlation")) or ev.get("surface") \
                or channel == "proven":
            out.append("confirmed from the internet")
        elif channel == "queryable" or channel.startswith("Web API") \
                or ev.get("webapi_enabled") is True:
            out.append("queryable on /_api")
        elif channel.startswith("page render") or channel == "render-only":
            out.append("not on /_api, page render only")
        elif ev.get("webapi_enabled") is False:
            out.append("not on /_api")

        if ev.get("visitor_controlled_input") is True:
            out.append("query steered by request input")
        elif "query_constraints" in ev:
            constraints = str(ev.get("query_constraints") or "")
            low = constraints.lower()
            if not constraints or constraints == "(none detected)":
                out.append("no filter in the query")
            elif "filter" in low or "condition" in low:
                out.append("bounded by a FetchXML filter")
            elif "row limit" in low:
                out.append("bounded by a row limit")
            elif "user" in low:
                out.append("bounded to the signed-in user")
            else:
                out.append(f"bounded by {constraints}")

        write_channel = ev.get("write_channel")
        if write_channel == "api":
            out.append("writable on /_api")
        elif write_channel == "form":
            out.append("reachable through a form")
        elif write_channel == "none":
            out.append("nothing writes to it today")

        if str(ev.get("webapi_fields", "")) == "*":
            out.append("every column published")
        return out[:3]

    @property
    def mitigation(self) -> tuple[str, str]:
        """Whether something already limits this, as (label, kind).

        ``kind`` is ``open``, ``partial`` or ``ok``, for the renderers to colour.
        A list of severities with nothing saying "a filter already bounds this"
        reads as a site on fire, and a reader who concludes that on the first
        row does not reach the row that matters. An empty label means the
        evidence does not say either way — better silent than reassuring.
        """
        ev = self.evidence
        channel = str(ev.get("channel", ""))

        if self.source.startswith(("anon", "correlation")) or ev.get("surface") \
                or channel == "proven":
            return ("Confirmed exposed", "open")
        if ev.get("visitor_controlled_input") is True:
            return ("Not mitigated", "open")
        if (ev.get("write_channel") == "api" or channel == "queryable"
                or channel.startswith("Web API") or ev.get("webapi_enabled") is True):
            return ("Not mitigated", "open")
        if ev.get("write_channel") == "none":
            return ("Mitigated", "ok")
        if "query_constraints" in ev:
            constraints = str(ev.get("query_constraints") or "")
            if constraints and constraints != "(none detected)":
                return ("Mitigated", "ok")
            return ("Partly mitigated", "partial")
        if (channel.startswith("page render") or channel == "render-only"
                or ev.get("webapi_enabled") is False):
            return ("Partly mitigated", "partial")
        return ("", "")


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
        # By subject rather than table, so findings that name a setting or a role
        # instead of a table still group with their own kind.
        return sorted(self.findings,
                      key=lambda f: (-int(f.severity), f.subject, f.title))

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
            where = f" ({f.subject})" if f.subject else ""
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
