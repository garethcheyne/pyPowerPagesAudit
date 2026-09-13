"""Finds where a table or column is actually *rendered*, and at which URL.

A table permission says what the security model allows. It does not say whether
anything on the site ever asks for the data. That distinction decides how a
finding should be read:

* Web API enabled — a visitor composes their own query. The permission is the
  only limit, so the whole table is reachable.
* No Web API — the data only appears where a page puts it. The exposure is
  bounded by the page, not the permission, and a reviewer needs the URL to
  judge it.

This module supplies the second case. It scans every content source the site
renders from — web templates (Liquid), web page copy and custom JavaScript,
content snippets, entity list view/filter FetchXML — for references to a table
and its columns, then resolves each hit back to a browsable URL.

Recognised reference styles:

* FetchXML ``<entity name="x">`` / ``<link-entity name="x">`` /
  ``<attribute name="col">``, whether inside ``{% fetchxml %}`` or an entity
  list's filter criteria.
* Liquid ``{% entitylist %}``, ``{% entityview %}``, ``{% chart %}``,
  ``{% include %}``, and ``entities['x']`` / ``entities.x`` lookups.
* Portal Web API calls in JavaScript — ``/_api/xs?$select=col`` and
  ``/_odata/...`` — which is how a page reaches data the permission allows but
  the server-side template never touches.
* Column reads on a Liquid record object, e.g. ``{{ row.emailaddress1 }}``.

Matching is deliberately generous. The output is a pointer for a human to open
and confirm, not a verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Liquid/FetchXML/JS constructs that name an entity.
_ENTITY_PATTERNS: list[tuple[str, str]] = [
    (r"<\s*entity\s+name\s*=\s*[\"']{t}[\"']", "FetchXML <entity>"),
    (r"<\s*link-entity\s+name\s*=\s*[\"']{t}[\"']", "FetchXML <link-entity>"),
    (r"\{%-?\s*entitylist\b[^%]*?[\"']{t}[\"']", "Liquid {% entitylist %}"),
    (r"\{%-?\s*entityview\b[^%]*?[\"']{t}[\"']", "Liquid {% entityview %}"),
    (r"\{%-?\s*chart\b[^%]*?[\"']{t}[\"']", "Liquid {% chart %}"),
    (r"entities\s*\[\s*[\"']{t}[\"']\s*\]", "Liquid entities['...']"),
    (r"entities\.{t}\b", "Liquid entities.<table>"),
    (r"/_api/{t}s?\b", "Web API call in page script"),
    (r"/_odata/{t}s?\b", "OData feed call in page script"),
    (r"[\"']logicalName[\"']\s*:\s*[\"']{t}[\"']", "Web API call in page script"),
]

# A column reference is only meaningful near an entity reference, except for
# FetchXML <attribute> which is unambiguous on its own.
_COLUMN_PATTERNS: list[tuple[str, str]] = [
    (r"<\s*attribute\s+name\s*=\s*[\"']{c}[\"']", "FetchXML <attribute>"),
    (r"\$select=[^\"'&\s]*\b{c}\b", "$select in a Web API call"),
    (r"\.{c}\b", "Liquid property read"),
    (r"\[\s*[\"']{c}[\"']\s*\]", "Liquid indexer read"),
]

_LIQUID_MARKERS = re.compile(r"\{%|\{\{|<fetch\b|\$select=|/_api/|/_odata/", re.I)


@dataclass
class ContentSource:
    """One piece of site content that can render data."""

    kind: str            # "Web template" | "Web page copy" | ...
    name: str
    text: str
    url: str = ""        # browsable URL, when the source maps to one
    page_names: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def renders_data(self) -> bool:
        return bool(self.text and _LIQUID_MARKERS.search(self.text))


@dataclass
class Reference:
    """One place a table (and optionally its columns) is referenced."""

    table: str
    kind: str
    source_name: str
    how: str
    url: str = ""
    line: int = 0
    snippet: str = ""
    columns: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table, "source_kind": self.kind,
            "source_name": self.source_name, "how": self.how, "url": self.url,
            "line": self.line, "snippet": self.snippet, "columns": self.columns,
            "note": self.note,
        }


def _compile(patterns: list[tuple[str, str]], value: str) -> list[tuple[re.Pattern, str]]:
    quoted = re.escape(value)
    return [(re.compile(p.replace("{t}", quoted).replace("{c}", quoted), re.I), how)
            for p, how in patterns]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _snippet(text: str, start: int, end: int, width: int = 110) -> str:
    """A single-line excerpt around the match, trimmed to something readable."""
    left = max(0, start - width // 2)
    right = min(len(text), end + width // 2)
    excerpt = " ".join(text[left:right].split())
    if left:
        excerpt = "…" + excerpt
    if right < len(text):
        excerpt += "…"
    return excerpt


class ReferenceIndex:
    """Scans a site's content sources for references to tables and columns."""

    def __init__(self, sources: Iterable[ContentSource]) -> None:
        self.sources = [s for s in sources if s.text]

    def find(self, table: str, columns: Iterable[str] = ()) -> list[Reference]:
        """Every reference to ``table``, annotated with any of ``columns`` seen nearby."""
        if not table or table.startswith("("):
            return []
        entity_res = _compile(_ENTITY_PATTERNS, table)
        column_res = {c: _compile(_COLUMN_PATTERNS, c) for c in columns if c}
        found: list[Reference] = []

        for source in self.sources:
            seen_lines: set[int] = set()
            for pattern, how in entity_res:
                for match in pattern.finditer(source.text):
                    line = _line_of(source.text, match.start())
                    if line in seen_lines:
                        continue
                    seen_lines.add(line)
                    found.append(Reference(
                        table=table, kind=source.kind, source_name=source.name,
                        how=how, url=source.url, line=line,
                        snippet=_snippet(source.text, match.start(), match.end()),
                        columns=self._columns_near(source.text, match.start(), column_res),
                        note=source.note))
        return sorted(found, key=lambda r: (r.url == "", r.source_name.lower(), r.line))

    @staticmethod
    def _columns_near(text: str, index: int, column_res: dict, window: int = 4000) -> list[str]:
        """Columns named in the same query block as the entity reference."""
        chunk = text[max(0, index - window // 4): index + window]
        return sorted({name for name, patterns in column_res.items()
                       if any(p.search(chunk) for p, _ in patterns)})

    def unreferenced(self, table: str) -> bool:
        return not self.find(table)
