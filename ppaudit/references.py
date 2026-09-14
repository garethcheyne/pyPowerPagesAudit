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

# Constraints inside a query block. Their presence means the page, not the
# permission, is deciding which rows come back — which is how a render-only
# channel is *supposed* to work.
_CONSTRAINTS: list[tuple[str, re.Pattern]] = [
    ("FetchXML <filter>", re.compile(r"<\s*filter\b", re.I)),
    ("FetchXML <condition>", re.compile(r"<\s*condition\b", re.I)),
    ("row limit", re.compile(r"\b(count|top)\s*=\s*[\"']\d+", re.I)),
    ("signed-in user context", re.compile(r"\b(user|request)\s*\.\s*(id|contactid|"
                                          r"parentcustomerid|adx_)", re.I)),
    ("Liquid guard", re.compile(r"\{%-?\s*(if|unless)\b", re.I)),
    ("permission-aware tag", re.compile(r"\{%-?\s*(entitylist|entityview|entityform)\b", re.I)),
]

# Visitor-supplied input reaching the query. This is the dangerous inverse of a
# filter: the page stops bounding the result and the visitor starts steering it,
# which turns a render-only page into a queryable endpoint.
_VISITOR_INPUT = re.compile(
    r"request\s*\.\s*params|params\s*\[|request\s*\.\s*query|"
    r"request\s*\.\s*body|\{\{\s*request\b", re.I)



@dataclass
class ContentSource:
    """One piece of site content that can render data."""

    kind: str            # "Web template" | "Web page copy" | ...
    name: str
    text: str
    url: str = ""        # browsable URL, when the source maps to one
    record_url: str = ""  # the Dataverse record holding this content
    page_id: str = ""     # the page serving it, for joining to page permissions
    page_names: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def renders_data(self) -> bool:
        return bool(self.text and _LIQUID_MARKERS.search(self.text))


@dataclass
class Reference:
    """One place a table (and optionally its columns) is referenced.

    Two links, because they answer different questions: ``url`` is where a
    visitor sees the data, ``config_url`` is the record you edit to change it.
    """

    table: str
    kind: str
    source_name: str
    how: str
    url: str = ""
    config_url: str = ""
    page_id: str = ""
    line: int = 0
    snippet: str = ""
    block: str = ""          # the query as written, for the reviewer to judge
    columns: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    visitor_input: bool = False
    client_side: bool = False
    note: str = ""

    @property
    def constrained(self) -> bool:
        """The query bounds its own result rather than returning the table.

        Client-side sources never count. Microsoft's guidance is explicit that
        presentation-layer filtering is not authorisation, because the visitor
        can edit or skip the script.
        """
        return bool(self.constraints) and not self.visitor_input and not self.client_side

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table, "source_kind": self.kind,
            "source_name": self.source_name, "how": self.how, "url": self.url,
            "config_url": self.config_url, "page_id": self.page_id,
            "line": self.line, "snippet": self.snippet, "block": self.block,
            "columns": self.columns, "constraints": self.constraints,
            "visitor_input": self.visitor_input, "client_side": self.client_side,
            "constrained": self.constrained, "note": self.note,
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
                    constraints, visitor_input, block = _analyse_block(
                        source.text, match.start())
                    found.append(Reference(
                        table=table, kind=source.kind, source_name=source.name,
                        how=how, url=source.url, config_url=source.record_url,
                        page_id=source.page_id, line=line,
                        snippet=_snippet(source.text, match.start(), match.end()),
                        block=block,
                        columns=self._columns_near(source.text, match.start(), column_res),
                        constraints=constraints, visitor_input=visitor_input,
                        client_side="javascript" in source.kind.lower(),
                        note=source.note))
        return sorted(found, key=lambda r: (r.url == "", r.source_name.lower(), r.line))

    @staticmethod
    def _columns_near(text: str, index: int, column_res: dict, window: int = 4000) -> list[str]:
        """Columns named in the same query as the entity reference.

        Scoped to the enclosing FetchXML or Liquid block where one exists. A
        plain character window bleeds columns between unrelated queries on the
        same page, which inflates severity by attributing personal data to
        whichever table happened to be nearby.
        """
        start, end = _enclosing_block(text, index)
        if start is None:
            start = max(0, index - window // 4)
            end = index + window
        chunk = text[start:end]
        return sorted({name for name, patterns in column_res.items()
                       if any(p.search(chunk) for p, _ in patterns)})

    def unreferenced(self, table: str) -> bool:
        return not self.find(table)


# Delimiters of a single query, innermost first.
_BLOCKS = [
    (re.compile(r"<\s*fetch\b", re.I), re.compile(r"</\s*fetch\s*>", re.I)),
    (re.compile(r"\{%-?\s*fetchxml\b", re.I), re.compile(r"\{%-?\s*endfetchxml\s*-?%\}", re.I)),
    (re.compile(r"\{%-?\s*entitylist\b", re.I), re.compile(r"\{%-?\s*endentitylist\s*-?%\}", re.I)),
    (re.compile(r"\{%-?\s*entityview\b", re.I), re.compile(r"\{%-?\s*endentityview\s*-?%\}", re.I)),
]


def _enclosing_block(text: str, index: int) -> tuple[int | None, int | None]:
    """Bounds of the innermost query block containing ``index``."""
    best: tuple[int | None, int | None] = (None, None)
    for opener, closer in _BLOCKS:
        starts = [m.start() for m in opener.finditer(text, 0, index + 1)]
        if not starts:
            continue
        start = starts[-1]
        closing = closer.search(text, index)
        end = closing.end() if closing else len(text)
        if best[0] is None or start > best[0]:
            best = (start, end)
    return best


def _analyse_block(text: str, index: int, max_block: int = 2400
                   ) -> tuple[list[str], bool, str]:
    """What constrains the query around ``index``, whether a visitor steers it,
    and the query itself so a reviewer can judge it without opening Dataverse."""
    start, end = _enclosing_block(text, index)
    if start is None:
        start, end = max(0, index - 500), index + 2000
    chunk = text[start:end]
    constraints = [label for label, pattern in _CONSTRAINTS if pattern.search(chunk)]
    block = _dedent(chunk[:max_block]) + ("\n…truncated…" if len(chunk) > max_block else "")
    return constraints, bool(_VISITOR_INPUT.search(chunk)), block


def _dedent(text: str) -> str:
    """Strip the common indentation so the excerpt reads at the report's margin."""
    lines = [line.rstrip() for line in text.strip("\n").splitlines()]
    indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
    trim = min(indents) if indents else 0
    return "\n".join(line[trim:] if len(line) >= trim else line for line in lines)
