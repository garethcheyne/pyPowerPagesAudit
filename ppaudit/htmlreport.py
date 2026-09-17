"""Fluent 2 HTML renderer for the Power Pages exposure audit.

The console and JSON renderers are for tooling; :mod:`ppaudit.markdown` is for
a document. This one is for the screen: a self-contained page a reviewer can
open, share and read top-down, styled to sit alongside the Power Platform
maker experience rather than look like tool output.

Design values are the Fluent 2 web light/dark theme ramps inlined as CSS custom
properties, because the report has to survive being emailed as a single file —
there is no bundler and no `FluentProvider` to emit them.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from . import docs
from .report import Report, Severity

# Fluent 2 status palette, mapped to severity.
SEVERITY_TOKENS = {
    Severity.CRITICAL: ("--sev-critical", "Critical"),
    Severity.HIGH: ("--sev-high", "High"),
    Severity.MEDIUM: ("--sev-medium", "Medium"),
    Severity.LOW: ("--sev-low", "Low"),
    Severity.INFO: ("--sev-info", "Info"),
}

_URL = re.compile(r"https?://[^\s,;<>\"')\]]+")


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _linkify(text: str) -> str:
    """Escape, then turn bare URLs into links so page references are clickable."""
    out, last = [], 0
    for match in _URL.finditer(text):
        out.append(_esc(text[last:match.start()]))
        url = match.group(0)
        out.append(f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">'
                   f'{_esc(url)}</a>')
        last = match.end()
    out.append(_esc(text[last:]))
    return "".join(out)


def _sev_class(severity: Severity) -> str:
    return f"sev-{severity.label.lower()}"


def _badge(severity: Severity) -> str:
    return (f'<span class="badge {_sev_class(severity)}">'
            f'{_esc(severity.label)}</span>')


def _mit_badge(finding) -> str:
    """Say up front whether something already limits a finding."""
    label, kind = finding.mitigation
    if not label:
        return ""
    return f'<span class="mit mit-{_esc(kind)}">{_esc(label)}</span>'


def _code(value: Any) -> str:
    return f"<code>{_esc(value)}</code>" if value not in (None, "") else ""


def _pill(text: str, kind: str = "") -> str:
    return f'<span class="pill {kind}">{_esc(text)}</span>'


def _table(headers: list[str], rows: Iterable[list[str]], empty: str) -> str:
    """Cells are pre-rendered HTML; callers escape their own values."""
    body = [r for r in rows]
    if not body:
        return f'<p class="empty">{_esc(empty)}</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                  for row in body)
    return ('<div class="grid-wrap"><table class="grid">'
            f"<thead><tr>{head}</tr></thead><tbody>{trs}</tbody></table></div>")


def _yes_no(flag: bool) -> str:
    return (f'<span class="flag {"on" if flag else "off"}">'
            f'{"Yes" if flag else "No"}</span>')


def _link(text: str, url: str, title: str = "") -> str:
    """Text as a link when a URL resolved, plain text when it did not."""
    if not url:
        return _esc(text)
    attr = f' title="{_esc(title)}"' if title else ""
    return (f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer"'
            f'{attr}>{_esc(text)}</a>')


def _record(model, key: str, record_id: str, text: str) -> str:
    return _link(text, model.record_url(key, record_id),
                 "Open this configuration record in Dataverse")


def _doc_links(title: str) -> str:
    """Microsoft Learn references for a finding — links only, never their text."""
    links = docs.for_finding(title)
    if not links:
        return ""
    items = "".join(
        f'<a class="doc" href="{_esc(l.url)}" target="_blank" rel="noopener '
        f'noreferrer">{_esc(l.title)}</a>' for l in links)
    return f'<div class="docs"><span class="docs-label">How to fix</span>{items}</div>'


def _timestamp(iso: str) -> str:
    """A run time that reads correctly wherever the report is opened.

    Rendered in the generating machine's local zone so the file is meaningful
    on its own, and tagged with the machine-readable UTC value so the script
    can re-render it in the reader's zone — these reports get emailed across
    timezones, and a bare UTC stamp invites the wrong conclusion about when an
    exposure was observed.
    """
    try:
        moment = datetime.fromisoformat(iso).astimezone()
    except (TypeError, ValueError):
        return _esc(iso)
    label = moment.strftime("%d %b %Y, %H:%M")
    zone = moment.strftime("%Z") or moment.strftime("%z")
    return (f'<time class="ts" datetime="{_esc(iso)}">'
            f'{_esc(label)} {_esc(zone)}</time>')


# --- sections ----------------------------------------------------------------


def _header(report: Report) -> str:
    ctx = report.context
    models = getattr(report, "models", []) or []
    domains = [w.primary_domain for m in models
               for w in getattr(m, "websites", []) if getattr(w, "primary_domain", "")]
    generations = ctx.get("config_generations", [])
    published = ctx.get("published_release") or {}

    def _titled_code(value: str) -> str:
        """A code chip that shows its full value on hover, since cells truncate."""
        return f'<code title="{_esc(value)}">{_esc(value)}</code>' if value else ""

    portal = ctx.get("portal_url") or ""
    dataverse = ctx.get("dataverse_url") or report.target
    version = (f'{_titled_code(ctx["portal_version"])}'
               f'<span class="meta-note">{_esc(ctx.get("portal_version_source", ""))}</span>'
               ) if ctx.get("portal_version") else ""
    latest = (f'{_titled_code(published["version"])}'
              f'<span class="meta-note">latest from Microsoft</span>') if published else ""
    config_model = ", ".join(
        f'{_esc(g["label"])} <code>{_esc(g["generation"])}_*</code>' for g in generations)
    content = (f'{_esc(ctx["content_sources_scanned"])}'
               '<span class="meta-note">templates, pages, snippets, lists</span>'
               ) if ctx.get("content_sources_scanned") else ""

    # One flat, uniform grid, ordered site -> environment -> this audit. No group
    # sub-columns: they forced long URLs into narrow cells that broke mid-word.
    items: list[tuple[str, str]] = [
        ("Portal", f'<a href="{_esc(portal)}" title="{_esc(portal)}" target="_blank" '
                   f'rel="noopener noreferrer">{_esc(portal)}</a>' if portal else ""),
        ("Primary domain", _titled_code(domains[0]) if domains else ""),
        ("Dataverse", _titled_code(dataverse)),
        ("Power Pages version", version),
        ("Latest release", latest),
        ("Configuration model", config_model),
        ("Run", _timestamp(report.started)),
        ("Identity", _titled_code(ctx["whoami"]) if ctx.get("whoami") else ""),
        ("Content scanned", content),
    ]
    meta_body = "".join(
        f'<div class="meta-item"><dt>{_esc(label)}</dt><dd>{value}</dd></div>'
        for label, value in items if value)

    instance = ctx.get("instance") or "Power Pages exposure audit"
    counts = report.counts()
    worst = next((s for s in reversed(Severity) if counts[s.label]), Severity.INFO)
    verdict = (f'{counts[worst.label]} {worst.label.lower()} '
               f'finding{"s" if counts[worst.label] != 1 else ""}')
    return f"""
<header class="hero">
  <div class="hero-top">
    {_logo()}
    <div class="hero-titles">
      <div class="eyebrow">Power Pages &middot; Dataverse exposure audit</div>
      <h1>{_esc(instance)}</h1>
    </div>
    <div class="hero-verdict {_sev_class(worst)}">
      <span class="hero-verdict-value">{counts[worst.label]}</span>
      <span class="hero-verdict-label">{_esc(worst.label)}</span>
    </div>
  </div>
  <p class="lede">What an unauthenticated visitor can reach through this site,
     and the configuration that allows it. Highest severity: {_esc(verdict)}.</p>
  <dl class="meta">{meta_body}</dl>
</header>"""


def _documentation() -> str:
    """A reference panel of official guidance. Links only \u2014 no copied content."""
    items = "".join(
        f'<li><a href="{_esc(l.url)}" target="_blank" rel="noopener noreferrer">'
        f'{_esc(l.title)}</a><span class="doc-url">{_esc(l.url)}</span></li>'
        for l in docs.GENERAL_DOCS)
    return f"""
<section id="documentation" class="card">
  <h2>Microsoft Learn reference</h2>
  <p>Official documentation for the features this report inspects. Individual
     findings link to the pages relevant to them; these cover the model as a
     whole. All links open on Microsoft Learn in your own locale.</p>
  <ul class="doc-list">{items}</ul>
</section>"""


# The product icon, inlined so the report stays a single shareable file.
# Used nominatively, to identify the Microsoft product being audited.
_LOGO_FILE = Path(__file__).with_name("_img") / "PP-Hero_Icon_PowerPages.svg"

_FALLBACK_LOGO = """
<svg class="logo" viewBox="0 0 48 48" role="img" aria-label="Power Pages audit">
  <defs>
    <linearGradient id="ppg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#66c2ff"/>
      <stop offset="55%" stop-color="#3b8ae2"/>
      <stop offset="100%" stop-color="#8b5cf6"/>
    </linearGradient>
  </defs>
  <rect x="6" y="3" width="28" height="38" rx="4" fill="url(#ppg)"/>
  <rect x="12" y="11" width="16" height="2.6" rx="1.3" fill="#fff" opacity=".95"/>
  <rect x="12" y="17" width="16" height="2.6" rx="1.3" fill="#fff" opacity=".75"/>
  <rect x="12" y="23" width="10" height="2.6" rx="1.3" fill="#fff" opacity=".55"/>
  <circle cx="33" cy="32" r="11" fill="#0b2a4a" opacity=".22"/>
  <circle cx="33" cy="32" r="9.5" fill="none" stroke="#fff" stroke-width="2.2"/>
  <path d="M23.5 32h19M33 22.5c4.6 5.4 4.6 13.6 0 19M33 22.5c-4.6 5.4-4.6 13.6 0 19"
        fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>
</svg>"""


@lru_cache(maxsize=1)
def _logo() -> str:
    """The product icon as inline SVG, sized by CSS rather than its own attributes.

    Element ids inside the file are namespaced on the way in: the report inlines
    the markup, and unprefixed ids like ``mask0`` would collide with anything
    else on the page that used the same generated names.
    """
    try:
        svg = _LOGO_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return _FALLBACK_LOGO

    svg = re.sub(r'\s(width|height)="[^"]*"', "", svg, count=2)
    svg = re.sub(r'\bid="([^"]+)"', r'id="pp-\1"', svg)
    svg = re.sub(r'url\(#([^)]+)\)', r"url(#pp-\1)", svg)
    svg = re.sub(r'href="#([^"]+)"', r'href="#pp-\1"', svg)
    svg = svg.replace(
        "<svg", '<svg class="logo" role="img" aria-label="Power Pages"', 1)
    return svg



def _summary(report: Report) -> str:
    counts = report.counts()
    cards = []
    for severity in reversed(Severity):
        count = counts[severity.label]
        cards.append(
            f'<div class="stat {_sev_class(severity)}{" is-zero" if not count else ""}">'
            f'<div class="stat-value">{count}</div>'
            f'<div class="stat-label">{_esc(severity.label)}</div></div>')
    actionable = [f for f in report.sorted() if f.severity >= Severity.MEDIUM]
    def _act_url(finding) -> str:
        url = str(finding.evidence.get("url") or "")
        if not url.startswith("http"):
            return ""
        return (f'<a class="act-url" href="{_esc(url)}" target="_blank" '
                f'rel="noopener noreferrer" title="Open the live page">{_esc(url)}</a>')

    items = "".join(
        f'<li>{_badge(f.severity)}{_mit_badge(f)}'
        f'<span class="act-title">{_esc(f.title)}</span>'
        f'{" " + _code(f.subject) if f.subject else ""}'
        + "".join(f'<span class="qual">{_esc(q)}</span>' for q in f.qualifiers)
        + _act_url(f)
        + "</li>"
        for f in actionable) or '<li class="empty">Nothing at Medium or above.</li>'
    return f"""
<section id="summary" class="card">
  <h2>Summary</h2>
  <div class="stats">{"".join(cards)}</div>
  <h3>Requiring action</h3>
  <p class="muted">Where the evidence settles it, a row carries a second badge
     saying what already limits it:
     <span class="mit mit-open">Confirmed exposed</span> the scanner read it from
     the internet, <span class="mit mit-open">Not mitigated</span> a queryable
     <code>/_api</code> channel, a visitor-steered query, or a live write channel,
     <span class="mit mit-partial">Partly mitigated</span> reachable only through
     a page or a form, which bounds what comes back,
     <span class="mit mit-ok">Mitigated</span> a filter bounds the query, or
     nothing exercises the permission. Rows with no badge are ones the evidence
     does not settle — open the finding. The grey notes say what each verdict
     rests on, and findings that name a page show its URL. Severity already
     accounts for all of this.</p>
  <ul class="action-list">{items}</ul>
</section>"""


def _anonymous(report: Report) -> str:
    matrix = getattr(report, "access_matrix", []) or []
    anon = [a for a in matrix if a.anonymous]
    if not matrix:
        return ""
    rows = []
    for a in sorted(anon, key=lambda x: (x.table.lower(), x.permission.lower())):
        scope = _pill(a.scope, "danger" if a.scope == "Global" else "")
        rows.append([
            _code(a.table),
            _link(a.permission, a.config_url, "Open this table permission in Dataverse"),
            scope,
            _esc(", ".join(a.privileges) or "(none)"),
            _yes_no(a.webapi_enabled),
            f'<span class="muted">{_esc(a.readable_columns)}</span>',
        ])
    flagged = sorted({c for a in anon for c in a.sensitive_columns})
    banner = ""
    if flagged:
        banner = ('<div class="callout warn"><strong>Personal-data columns reachable '
                  'anonymously:</strong> '
                  + " ".join(_code(c) for c in flagged) + "</div>")
    return f"""
<section id="anonymous" class="card">
  <h2>Anonymous access</h2>
  <p>Everything bound to a web role flagged as the <strong>Anonymous Users role</strong>
     is reachable by anyone on the internet, with no sign-in. <code>Global</code> scope
     means every row; <code>Contact</code>/<code>Account</code>/<code>Self</code>/<code>Parent</code>
     resolve against the signed-in contact, which an anonymous visitor does not have.</p>
  {banner}
  {_table(["Table", "Permission", "Scope", "Privileges", "Web API", "Columns reachable"],
          rows, "No table permission is bound to an anonymous web role.")}
</section>"""


def _references(report: Report) -> str:
    refs = getattr(report, "references", {}) or {}
    populated = {t: r for t, r in refs.items() if r}
    if not populated:
        return ""
    blocks = []
    for table in sorted(populated):
        rows = []
        for ref in populated[table]:
            rows.append([
                _esc(f"{ref.kind} — {ref.source_name}"),
                _link("View page", ref.url, "Open the live page on the portal")
                or '<span class="muted">—</span>',
                _link("Edit record", ref.config_url,
                      "Open the Dataverse record holding this content")
                or '<span class="muted">—</span>',
                f'<span class="muted">{_esc(ref.how)}, line {ref.line}</span>',
                (_pill("visitor input", "danger") if ref.visitor_input
                 else _esc(", ".join(ref.constraints))
                 or '<span class="muted">unfiltered</span>'),
                " ".join(_code(c) for c in ref.columns) or '<span class="muted">—</span>',
                (f'<details class="query"><summary>show query</summary>'
                 f'<pre>{_esc(ref.block)}</pre></details>' if ref.block
                 else f'<code class="snippet">{_esc(ref.snippet)}</code>'),
            ])
        blocks.append(
            f'<details class="ref"><summary><code>{_esc(table)}</code>'
            f'<span class="count">{len(populated[table])} reference(s)</span></summary>'
            + _table(["Source", "Portal", "Dataverse", "How", "Query bounds",
                      "Columns", "Query"], rows, "none")
            + "</details>")
    return f"""
<section id="rendered" class="card">
  <h2>Where the data is rendered</h2>
  <p>Found by scanning the site's Liquid web templates, web page copy and scripts,
     content snippets and entity list FetchXML. Where the Web API is off, the page
     is the only channel, so the page is what bounds the exposure.</p>
  <p><strong>Portal</strong> opens the live page to see what it actually returns.
     <strong>Dataverse</strong> opens the record that holds the Liquid or FetchXML,
     which is what you edit to change it.</p>
  <p><strong>Query bounds</strong> is what the query does to limit its own result.
     With the Web API off the page renders server-side, so a filtered query is
     usually publishing by design. <code>visitor input</code> is the opposite: the
     query is built from request parameters, so the visitor steers it.</p>
  {"".join(blocks)}
</section>"""


def _external(report: Report) -> str:
    exposed = report.context.get("anon_exposed_tables")
    if not exposed:
        return ""
    chips = " ".join(_code(t) for t in exposed)
    return f"""
<section id="external" class="card">
  <h2>External scan (unauthenticated, outside-in)</h2>
  <p>Tables the anonymous scanner read from the public internet with no credentials.
     These are confirmed, not theoretical.</p>
  <div class="chipline">{chips}</div>
</section>"""


def _findings(report: Report) -> str:
    groups: dict[Severity, list] = {}
    for finding in report.sorted():
        groups.setdefault(finding.severity, []).append(finding)
    blocks = []
    for severity in reversed(Severity):
        items = groups.get(severity)
        if not items:
            continue
        cards = []
        for f in items:
            evidence = ""
            query = str(f.evidence.get("query") or "")
            rows = {k: v for k, v in f.evidence.items() if k != "query"}
            if rows:
                evidence = "".join(
                    f'<div class="ev-row"><dt>{_esc(k)}</dt>'
                    f'<dd>{_linkify(str(v))}</dd></div>'
                    for k, v in rows.items())
                evidence = f'<dl class="evidence">{evidence}</dl>'
            if query:
                evidence += (f'<details class="query"><summary>Query as written '
                             f'&mdash; judge whether it bounds the result</summary>'
                             f'<pre>{_esc(query)}</pre></details>')
            detail = _linkify(f.detail).replace("\n", "<br>") if f.detail else ""
            cards.append(
                f'<article class="finding {_sev_class(severity)}">'
                f'<div class="finding-head">{_badge(severity)}{_mit_badge(f)}'
                f'<h4>{_esc(f.title)}</h4>'
                f'{_code(f.subject)}'
                f'<span class="src">{_esc(f.source)}</span></div>'
                f'<p class="finding-detail">{detail}</p>{evidence}'
                f'{_doc_links(f.title)}</article>')
        blocks.append(
            f'<h3 class="sev-heading {_sev_class(severity)}">{_esc(severity.label)}'
            f'<span class="count">{len(items)}</span></h3>' + "".join(cards))
    return f"""
<section id="findings" class="card">
  <h2>Findings</h2>
  {"".join(blocks) or '<p class="empty">No findings recorded.</p>'}
</section>"""


def _configuration(report: Report) -> str:
    models = [m for m in (getattr(report, "models", []) or [])
              if getattr(m, "in_use", True)]
    if not models:
        return ""
    blocks = []
    for model in models:
        roles = _table(
            ["Web role", "Type", "Table permissions", "Column profiles", "Page rules"],
            [[_record(model, "webrole", r.id, r.name),
              _pill(r.kind, "danger" if r.is_anonymous else ""),
              _esc(len(model.permissions_for_role(r.name))),
              _esc(sum(1 for p in model.profiles if r.name in p.roles)),
              _esc(sum(1 for p in model.page_rules if r.name in p.roles))]
             for r in sorted(model.roles,
                             key=lambda x: (not x.is_anonymous, x.name.lower()))],
            "No web roles.")

        permissions = _table(
            ["Table", "Permission", "Scope", "Privileges", "Web roles", "Web API"],
            [[_code(p.table),
              _record(model, "entitypermission", p.id, p.name),
              _pill(p.scope or "unset", "danger" if p.scope == "Global" else ""),
              _esc(", ".join(p.privileges()) or "(none)"),
              _esc(", ".join(p.roles)) or '<span class="muted">(unbound)</span>',
              _yes_no(bool(model.webapi_for(p.table)
                           and model.webapi_for(p.table).enabled))]
             for p in sorted(model.permissions,
                             key=lambda x: (x.table.lower(), x.name.lower()))],
            "No table permissions.")

        webapi = _table(
            ["Table", "Enabled", "Published columns", "Site settings"],
            [[_code(w.entity), _yes_no(w.enabled),
              _esc(w.fields_raw or "*")
              + (' <span class="pill danger">all columns</span>' if w.all_fields else ""),
              " ".join(filter(None, [
                  _record(model, "sitesetting", w.enabled_setting_id, "enabled")
                  if w.enabled_setting_id else "",
                  _record(model, "sitesetting", w.fields_setting_id, "fields")
                  if w.fields_setting_id else ""])) or '<span class="muted">—</span>']
             for w in model.webapi if w.enabled],
            "No table has Webapi/<entity>/enabled = true.")

        profiles = _table(
            ["Profile", "Table", "All-column default", "Web roles", "Per-column grants"],
            [[_record(model, "columnpermissionprofile", p.id, p.name), _code(p.table),
              _esc(", ".join(p.all_permissions) or "(none)"),
              _esc(", ".join(p.roles)) or '<span class="muted">(unbound)</span>',
              _esc(", ".join(f"{c.column}: {'/'.join(c.permissions)}"
                             for c in p.columns) or "(none)")]
             for p in model.profiles],
            "No column permission profiles.")

        sites = _table(
            ["Website", "Record"],
            [[_esc(w.name), _record(model, "website", w.id, w.id or "—")]
             for w in model.websites],
            "No websites.")

        blocks.append(f"""
  <h3>{_esc(model.label)} <code>{_esc(model.generation)}_*</code></h3>
  <p class="muted">{_esc(model.description)}</p>
  <p class="muted">Record names link to the configuration record in Dataverse.</p>
  <h4>Websites</h4>{sites}
  <h4>Web roles</h4>{roles}
  <h4>Table permissions</h4>{permissions}
  <h4>Web API site settings</h4>{webapi}
  <h4>Column permission profiles</h4>{profiles}""")
    return f"""
<section id="configuration" class="card">
  <h2>Configuration detail</h2>
  {"".join(blocks)}
</section>"""


def _state_pill(resource) -> str:
    """Flag content the site does not serve because of its publishing state."""
    if getattr(resource, "live", True):
        return ""
    label = getattr(resource, "state", "") or "not published"
    return (f' <span class="pill" title="Publishing state is not a visible one, so '
            f'the site does not serve this to visitors">{_esc(label)}</span>')


def _published(report: Report) -> str:
    """Live URLs the site serves: web pages, web files, and data endpoints.

    Everything here is a link a reviewer can click to see what the site actually
    returns, rather than a configuration record describing what it should return.
    """
    ctx = report.context
    models = [m for m in (getattr(report, "models", []) or [])
              if getattr(m, "in_use", True)]

    base = (ctx.get("portal_url") or "").rstrip("/")
    if not base:
        domain = next((w.primary_domain for m in models
                       for w in getattr(m, "websites", [])
                       if getattr(w, "primary_domain", "")), "")
        if domain:
            base = "https://" + domain.replace("https://", "").replace("http://", "").rstrip("/")

    def url_cell(url: str) -> str:
        return _link(url, url, "Open in a new tab") if url else '<span class="muted">—</span>'

    probes = ctx.get("url_probes") or {}
    _verdict_pill = {"open": "warn", "gated": "ok", "not found": "", "error": ""}

    def anon_cell(url: str) -> str:
        p = probes.get(url)
        if not p:
            return '<span class="muted">—</span>'
        verdict = p.get("verdict", "")
        status = p.get("status")
        kind = _verdict_pill.get(verdict, "")
        label = verdict + (f" {status}" if status and verdict in ("open", "error") else "")
        title = f"HTTP {status} — anonymous GET landed on {p.get('final_path', '')}"
        cls = f"pill {kind}".strip()
        return f'<span class="{cls}" title="{_esc(title)}">{_esc(label)}</span>'

    pages = [r for m in models for r in m.published_pages(base)]
    files = [r for m in models for r in m.published_files(base)]
    orphans = sum(1 for r in pages if r.orphan)

    def probe_summary(rows) -> str:
        if not probes:
            return ""
        tally: dict[str, int] = {}
        for r in rows:
            v = (probes.get(r.url) or {}).get("verdict")
            if v:
                tally[v] = tally.get(v, 0) + 1
        if not tally:
            return ""
        order = ["open", "gated", "not found", "error"]
        parts = " · ".join(f"{tally[v]} {v}" for v in order if v in tally)
        return f'<p class="muted">Anonymous probe: {parts}.</p>'

    pages_table = _table(
        ["Page", "Path", "URL", "Anonymous", "Dataverse"],
        [[_esc(r.name)
          + (' <span class="pill warn" title="No parent page — reachable by URL but '
             'not in the site navigation">orphan</span>' if r.orphan else "")
          + _state_pill(r),
          _code(r.path), url_cell(r.url), anon_cell(r.url),
          _link("record", r.record_url, "Open the web page record in Dataverse")
          or '<span class="muted">—</span>']
         for r in pages],
        "No web pages found in the configuration.")

    files_table = _table(
        ["File", "URL", "Anonymous", "Dataverse"],
        [[_esc(r.name) + _state_pill(r), url_cell(r.url), anon_cell(r.url),
          _link("record", r.record_url, "Open the web file record in Dataverse")
          or '<span class="muted">—</span>']
         for r in files],
        "No web files found in the configuration.")

    # Data endpoints. When the anonymous probe ran, the verdict is what each URL
    # actually returned; each row is a real GET, not a guess from configuration.
    endpoint_base = base or report.target.rstrip("/")
    probed_eps = ctx.get("endpoint_probes") or []
    _ep_pill = {"leak": "danger", "denied": "ok", "reachable (no rows)": "warn",
                "reachable anonymously": "warn", "unavailable": "", "not found": "",
                "error": ""}

    def ep_result_cell(e: dict) -> str:
        verdict = e.get("verdict", "")
        status = e.get("status")
        kind = _ep_pill.get(verdict, "")
        cls = f"pill {kind}".strip()
        title = f"HTTP {status} — {e.get('note', '')}"
        return f'<span class="{cls}" title="{_esc(title)}">{_esc(verdict)}</span>'

    if probed_eps:
        endpoint_rows = [
            [_code(e["table"]), _esc(e["surface"]), url_cell(e["url"]), ep_result_cell(e)]
            for e in probed_eps]
        endpoint_count = len(probed_eps)
        endpoints_intro = (
            "Each row is an anonymous GET against the live endpoint. "
            "<code>leak</code> returned rows with no sign-in; <code>denied</code> "
            "answered but refused the read; <code>reachable (no rows)</code> is "
            "permitted but empty right now; <code>unavailable</code> means that "
            "surface is switched off site-wide.")
    else:
        # Fallback when probing was skipped (--no-probe): configuration only.
        endpoint_rows = []
        seen: set[tuple[str, str]] = set()

        def add_endpoint(table, surface, path, status, cls=""):
            key = (table, path)
            if key in seen:
                return
            seen.add(key)
            url = f"{endpoint_base}{path}" if endpoint_base else path
            endpoint_rows.append([_code(table), _esc(surface), url_cell(url),
                                  _pill(status, cls)])

        for model in models:
            for w in getattr(model, "webapi", []):
                if getattr(w, "enabled", False):
                    add_endpoint(w.entity, "Web API", f"/_api/{w.entity}", "enabled", "warn")
        endpoint_count = len(endpoint_rows)
        endpoints_intro = ("Web API surfaces enabled in configuration. Run without "
                           "<code>--no-probe</code> to test what each actually returns.")

    endpoints_table = _table(
        ["Table", "Surface", "URL", "Anonymous result"],
        endpoint_rows,
        "No data endpoints enabled in configuration, and none confirmed reachable.")

    orphan_note = (f' <span class="tab-count">{orphans} orphaned</span>'
                   if orphans else "")
    pages_probe_summary = probe_summary(pages)
    files_probe_summary = probe_summary(files)
    note = ("" if endpoint_base else
            '<p class="callout warn">No portal URL is known for this run, so URLs are '
            'shown as site-relative paths. Prefix them with the site domain to open them.</p>')

    return f"""
<section id="published" class="card">
  <h2>Published URLs</h2>
  <p>Everything the site serves at a live address: pages a visitor can browse,
     files it hosts, and the data endpoints an unauthenticated caller can hit.
     Every link opens the live resource so you can see exactly what it returns.</p>
  {note}
  <h3>Web pages <span class="count">{len(pages)}</span>{orphan_note}</h3>
  <p>One row per canonical page; language variants of the same page share a URL
     and are counted, not repeated. An <code>orphan</code> page has no parent, so
     it is reachable at its URL but does not appear in the site navigation —
     worth confirming each is meant to be public. <strong>Anonymous</strong> is
     what an unauthenticated GET actually returned: <code>open</code> = 200 with
     no sign-in, <code>gated</code> = redirected to sign-in (or 401/403),
     <code>not found</code> = 404. Compare it against the page's configured rules.
     A page tagged with a publishing state (such as <code>Draft</code>) is in a
     state the site does not serve — if one of those answers <code>open</code>,
     the state is not being enforced and is worth investigating.</p>
  {pages_probe_summary}
  {pages_table}
  <h3>Web files <span class="count">{len(files)}</span></h3>
  {files_probe_summary}
  {files_table}
  <h3>Data endpoints <span class="count">{endpoint_count}</span></h3>
  <p>{endpoints_intro}</p>
  {endpoints_table}
</section>"""


def render(report: Report) -> str:
    counts = report.counts()
    actionable = sum(counts[s.label] for s in Severity if s >= Severity.MEDIUM)
    panels = [
        ("summary", "Summary", None, _summary(report)),
        ("anonymous", "Anonymous access", None, _anonymous(report)),
        ("external", "External scan", None, _external(report)),
        ("rendered", "Where rendered", None, _references(report)),
        ("published", "Published URLs", None, _published(report)),
        ("findings", "Findings", actionable or None, _findings(report)),
        ("configuration", "Configuration", None, _configuration(report)),
        ("documentation", "Documentation", None, _documentation()),
    ]
    present = [(a, label, count, body) for a, label, count, body in panels if body]

    tabs = "".join(
        f'<button class="tab" role="tab" id="tab-{a}" aria-controls="panel-{a}" '
        f'aria-selected="{"true" if i == 0 else "false"}" '
        f'tabindex="{0 if i == 0 else -1}" data-panel="{a}">{_esc(label)}'
        + (f'<span class="tab-count">{count}</span>' if count else "")
        + "</button>"
        for i, (a, label, count, _) in enumerate(present))

    sections = "".join(
        f'<div class="panel" role="tabpanel" id="panel-{a}" aria-labelledby="tab-{a}"'
        f'{"" if i == 0 else " hidden"}>{body}</div>'
        for i, (a, _, _, body) in enumerate(present))

    return _TEMPLATE.format(
        title=_esc(report.context.get("instance") or "Power Pages exposure audit"),
        header=_header(report),
        tabs=f'<nav class="tabs" role="tablist" aria-label="Report sections">{tabs}</nav>',
        body=sections,
        styles=_STYLES,
        script=_SCRIPT,
    )


# Tabs are progressive enhancement: without JS every panel is simply visible.
_SCRIPT = """
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab'));
  if (!tabs.length) { return; }

  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      document.getElementById('panel-' + t.dataset.panel).hidden = !on;
    });
    if (focus) { tab.focus(); }
    history.replaceState(null, '', '#' + tab.dataset.panel);
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () { select(tab, false); });
    tab.addEventListener('keydown', function (e) {
      var i = tabs.indexOf(tab), next = null;
      if (e.key === 'ArrowRight') { next = tabs[(i + 1) % tabs.length]; }
      if (e.key === 'ArrowLeft') { next = tabs[(i - 1 + tabs.length) % tabs.length]; }
      if (e.key === 'Home') { next = tabs[0]; }
      if (e.key === 'End') { next = tabs[tabs.length - 1]; }
      if (next) { e.preventDefault(); select(next, true); }
    });
  });

  var initial = tabs.filter(function (t) {
    return '#' + t.dataset.panel === location.hash;
  })[0];
  if (initial) { select(initial, false); }

  // Printing must not hide six of seven sections.
  window.addEventListener('beforeprint', function () {
    tabs.forEach(function (t) {
      document.getElementById('panel-' + t.dataset.panel).hidden = false;
    });
  });
  window.addEventListener('afterprint', function () {
    select(tabs.filter(function (t) {
      return t.getAttribute('aria-selected') === 'true';
    })[0] || tabs[0], false);
  });
})();

// Re-render timestamps in the reader's timezone, not the auditor's.
(function () {
  Array.prototype.forEach.call(document.querySelectorAll('time.ts'), function (el) {
    var when = new Date(el.getAttribute('datetime'));
    if (isNaN(when)) { return; }
    try {
      el.textContent = when.toLocaleString(undefined, {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
      });
      el.title = when.toISOString() + ' (UTC)';
    } catch (e) { /* keep the server-rendered value */ }
  });
})();
"""


_STYLES = """
:root {
  color-scheme: light;
  /* Fluent 2 - neutral ramp (web light theme) */
  --bg-canvas: #f5f5f5;
  --bg-surface: #ffffff;
  --bg-subtle: #fafafa;
  --bg-muted: #f0f0f0;
  --fg-1: #242424;
  --fg-2: #424242;
  --fg-3: #616161;
  --stroke-1: #d1d1d1;
  --stroke-2: #e0e0e0;
  /* Fluent 2 - brand ramp */
  --brand-70: #115ea3;
  --brand-80: #0f6cbd;
  --brand-100: #479ef5;
  --brand-160: #ebf3fc;
  --brand-shade: #0c3b5e;
  /* Fluent 2 - status palette */
  --sev-critical: #bc2f32;
  --sev-critical-bg: #fdf3f4;
  --sev-critical-stroke: #f1bbbc;
  --sev-high: #c43501;
  --sev-high-bg: #fdf6f3;
  --sev-high-stroke: #f4bfab;
  --sev-medium: #835b00;
  --sev-medium-bg: #fdf9f0;
  --sev-medium-stroke: #f0d3a0;
  --sev-low: #0f6cbd;
  --sev-low-bg: #ebf3fc;
  --sev-low-stroke: #b4d6fa;
  --sev-info: #616161;
  --sev-info-bg: #f5f5f5;
  --sev-info-stroke: #e0e0e0;
  --ok: #0e700e;
  /* Fluent 2 - radius, shadow, type */
  --r-md: 4px;
  --r-lg: 6px;
  --r-xl: 8px;
  --r-circular: 9999px;
  --shadow-2: 0 1px 2px rgba(0,0,0,.14), 0 0 2px rgba(0,0,0,.12);
  --shadow-4: 0 2px 4px rgba(0,0,0,.14), 0 0 2px rgba(0,0,0,.12);
  --shadow-16: 0 8px 16px rgba(0,0,0,.14), 0 0 2px rgba(0,0,0,.12);
  --font: "Segoe UI Variable Text", "Segoe UI", -apple-system, BlinkMacSystemFont,
          Roboto, "Helvetica Neue", sans-serif;
  --font-display: "Segoe UI Variable Display", "Segoe UI Variable Text", "Segoe UI",
          -apple-system, sans-serif;
  --mono: Consolas, "Cascadia Code", "Courier New", monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg-canvas); color: var(--fg-1);
  font-family: var(--font); font-size: 14px; line-height: 20px;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--brand-80); text-decoration: none; }
a:hover { text-decoration: underline; }

/* --- hero: the light Power Pages masthead -------------------------------
   Colours sampled from the product page hero. Redrawn as CSS gradients
   rather than hotlinking the CDN asset, so the report stays a single file
   that renders offline and calls nothing on open. */
.hero {
  position: relative; overflow: hidden;
  background:
    radial-gradient(700px 300px at 88% 18%, rgba(0,119,211,.55), transparent 62%),
    radial-gradient(520px 260px at 66% 74%, rgba(191,181,231,.60), transparent 66%),
    radial-gradient(420px 220px at 78% 46%, rgba(126,190,228,.50), transparent 68%),
    linear-gradient(180deg, #f8f8f8 0%, #f3f3f3 100%);
  color: var(--fg-1);
  border-bottom: 1px solid var(--stroke-2);
  padding: 32px 32px 26px;
}
/* The ribbon sweep, so the panel reads as Power Pages rather than a wash. */
.hero::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(1100px 150px at 108% 8%, rgba(42,81,148,.50), transparent 55%),
    radial-gradient(800px 120px at 52% 96%, rgba(189,181,230,.45), transparent 60%);
}
.hero-top, .lede, .meta { position: relative; z-index: 1; }
.hero-top { display: flex; align-items: center; gap: 18px; margin-bottom: 10px; }
.logo { width: 52px; height: 52px; flex: none;
        filter: drop-shadow(0 1px 3px rgba(0,0,0,.18)); }
.hero-titles { min-width: 0; }
.hero-verdict {
  margin-left: auto; text-align: center; flex: none;
  background: rgba(255,255,255,.72); border: 1px solid var(--stroke-1);
  border-radius: var(--r-lg); padding: 8px 18px;
  box-shadow: var(--shadow-2);
}
.hero-verdict-value { display: block; font-family: var(--font-display);
                      font-size: 26px; line-height: 30px; font-weight: 600; }
.hero-verdict-label { display: block; font-size: 11px; font-weight: 600;
                      text-transform: uppercase; letter-spacing: .06em; }
.hero-verdict.sev-critical { color: var(--sev-critical); }
.hero-verdict.sev-high     { color: var(--sev-high); }
.hero-verdict.sev-medium   { color: var(--sev-medium); }
.hero-verdict.sev-low      { color: var(--sev-low); }
.hero-verdict.sev-info     { color: var(--sev-info); }
.eyebrow {
  text-transform: uppercase; letter-spacing: .08em; font-size: 12px;
  font-weight: 600; color: var(--brand-70); margin-bottom: 2px;
}
.hero h1 {
  font-family: var(--font-display); font-size: 28px; line-height: 36px;
  font-weight: 600; margin: 0; color: var(--fg-1);
}
.lede { margin: 0 0 20px; font-size: 15px; line-height: 21px;
        max-width: 78ch; color: var(--fg-2); }
/* Grouped by question rather than a flat run of values, with a rule between
   columns so the groups read as groups. */
.meta { display: grid; gap: 14px 30px; margin: 18px 0 0; justify-content: start;
        grid-template-columns: repeat(auto-fill, minmax(184px, 214px)); }
.meta-item { min-width: 0; }
.meta-item dt {
  font-size: 10.5px; line-height: 14px; margin: 0 0 3px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .07em; color: var(--brand-70);
}
.meta-item dd { margin: 0; font-size: 13.5px; line-height: 18px; color: var(--fg-1);
                white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.meta-item dd a, .meta-item dd code { max-width: 100%; }
.meta-note { display: block; font-size: 11px; line-height: 15px; font-weight: 400;
             color: var(--fg-3); margin-top: 2px;
             white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.meta a { color: var(--brand-70); }
.meta code { background: rgba(255,255,255,.75); border: 1px solid var(--stroke-2); }
.meta time { border-bottom: 1px dotted var(--fg-3); cursor: help; }

/* --- tabs --------------------------------------------------------------- */
.tabs {
  position: sticky; top: 0; z-index: 5;
  background: var(--bg-surface); border-bottom: 1px solid var(--stroke-2);
  padding: 0 32px; display: flex; gap: 2px; overflow-x: auto;
  box-shadow: var(--shadow-2);
}
.tab {
  appearance: none; background: none; border: 0; cursor: pointer;
  font-family: inherit; font-size: 14px; font-weight: 600; color: var(--fg-2);
  padding: 12px 16px 10px; white-space: nowrap; display: flex; align-items: center;
  gap: 8px; border-bottom: 2px solid transparent; border-radius: var(--r-md) var(--r-md) 0 0;
}
.tab:hover { background: var(--bg-subtle); color: var(--fg-1); }
.tab:focus-visible { outline: 2px solid var(--brand-80); outline-offset: -2px; }
.tab[aria-selected="true"] { color: var(--brand-70); border-bottom-color: var(--brand-80); }
.tab-count {
  font-size: 11px; font-weight: 700; background: var(--sev-critical-bg);
  color: var(--sev-critical); border: 1px solid var(--sev-critical-stroke);
  border-radius: var(--r-circular); padding: 0 7px; line-height: 17px;
}
.panel[hidden] { display: none; }

/* --- documentation links ------------------------------------------------- */
.docs {
  display: flex; flex-wrap: wrap; align-items: center; gap: 6px;
  margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--stroke-2);
}
.docs-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: var(--fg-3); margin-right: 2px;
}
.doc {
  font-size: 12px; font-weight: 600; padding: 2px 10px;
  background: var(--brand-160); color: var(--brand-70);
  border: 1px solid var(--sev-low-stroke); border-radius: var(--r-circular);
}
.doc:hover { background: var(--sev-low-bg); text-decoration: none;
             border-color: var(--brand-80); }
.doc::after { content: " \\2197" / ""; font-weight: 400; }
.doc-list { list-style: none; margin: 0; padding: 0;
            display: grid; gap: 8px;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
.doc-list li {
  border: 1px solid var(--stroke-2); border-radius: var(--r-lg);
  padding: 10px 14px; background: var(--bg-subtle);
}
.doc-list a { font-weight: 600; display: block; }
.doc-url { display: block; font-size: 11px; color: var(--fg-3);
           font-family: var(--mono); word-break: break-all; margin-top: 2px; }

/* --- layout ------------------------------------------------------------- */
main { max-width: none; margin: 0; padding: 24px 32px 64px; }
.card {
  background: var(--bg-surface); border: 1px solid var(--stroke-2);
  border-radius: var(--r-xl); box-shadow: var(--shadow-2);
  padding: 24px; margin-bottom: 20px; scroll-margin-top: 60px;
}
h2 {
  font-family: var(--font-display); font-size: 20px; line-height: 28px;
  font-weight: 600; margin: 0 0 12px;
}
h3 { font-size: 16px; line-height: 22px; font-weight: 600; margin: 24px 0 10px; }
h4 { font-size: 14px; line-height: 20px; font-weight: 600; margin: 20px 0 8px;
     color: var(--fg-2); }
p { margin: 0 0 12px; color: var(--fg-2); max-width: 90ch; }
.muted { color: var(--fg-3); }
.empty { color: var(--fg-3); font-style: italic; }

/* --- stats -------------------------------------------------------------- */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
         gap: 12px; margin-bottom: 8px; }
.stat {
  border: 1px solid var(--stroke-2); border-radius: var(--r-lg);
  border-top: 3px solid currentColor; padding: 14px 16px; background: var(--bg-subtle);
}
.stat.is-zero { opacity: .45; }
.stat-value { font-family: var(--font-display); font-size: 28px; line-height: 32px;
              font-weight: 600; color: var(--fg-1); }
.stat-label { font-size: 12px; line-height: 16px; font-weight: 600;
              text-transform: uppercase; letter-spacing: .04em; }
.stat.sev-critical { color: var(--sev-critical); }
.stat.sev-high     { color: var(--sev-high); }
.stat.sev-medium   { color: var(--sev-medium); }
.stat.sev-low      { color: var(--sev-low); }
.stat.sev-info     { color: var(--sev-info); }

.action-list { list-style: none; margin: 0; padding: 0; }
.action-list li {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 8px 0; border-bottom: 1px solid var(--stroke-2);
}
.action-list li:last-child { border-bottom: 0; }
.act-title { font-weight: 600; color: var(--fg-1); }
/* Is anything already limiting this? Read before the reader panics. */
.mit {
  display: inline-block; padding: 2px 10px; border-radius: var(--r-circular);
  font-size: 12px; line-height: 16px; font-weight: 600; white-space: nowrap;
  border: 1px solid;
}
.mit-ok { color: var(--ok); background: rgba(14,112,14,.10);
          border-color: rgba(14,112,14,.35); }
.mit-partial { color: var(--sev-medium); background: var(--sev-medium-bg);
               border-color: var(--sev-medium-stroke); }
.mit-open { color: var(--sev-critical); background: var(--sev-critical-bg);
            border-color: var(--sev-critical-stroke); }
.act-url { font-size: 12px; font-family: var(--mono); word-break: break-all;
           flex-basis: 100%; }
/* What bounds or confirms a finding: present, but never louder than the title. */
.qual {
  font-size: 11px; line-height: 16px; color: var(--fg-3);
  background: var(--bg-muted); border: 1px solid var(--stroke-2);
  border-radius: var(--r-circular); padding: 1px 8px; white-space: nowrap;
}

/* --- badges, pills, chips ----------------------------------------------- */
.badge {
  display: inline-block; padding: 2px 10px; border-radius: var(--r-circular);
  font-size: 12px; line-height: 16px; font-weight: 600; white-space: nowrap;
  border: 1px solid;
}
.badge.sev-critical { color: var(--sev-critical); background: var(--sev-critical-bg);
                      border-color: var(--sev-critical-stroke); }
.badge.sev-high     { color: var(--sev-high); background: var(--sev-high-bg);
                      border-color: var(--sev-high-stroke); }
.badge.sev-medium   { color: var(--sev-medium); background: var(--sev-medium-bg);
                      border-color: var(--sev-medium-stroke); }
.badge.sev-low      { color: var(--sev-low); background: var(--sev-low-bg);
                      border-color: var(--sev-low-stroke); }
.badge.sev-info     { color: var(--sev-info); background: var(--sev-info-bg);
                      border-color: var(--sev-info-stroke); }
.pill {
  display: inline-block; padding: 1px 8px; border-radius: var(--r-circular);
  font-size: 12px; line-height: 16px; font-weight: 600;
  background: var(--bg-muted); color: var(--fg-2); white-space: nowrap;
}
.pill.danger { background: var(--sev-critical-bg); color: var(--sev-critical);
               border: 1px solid var(--sev-critical-stroke); }
.pill.warn { background: var(--sev-medium-bg); color: var(--sev-medium);
             border: 1px solid var(--sev-medium); }
.pill.ok { background: rgba(14,112,14,.10); color: var(--ok);
           border: 1px solid rgba(14,112,14,.35); }
.flag { font-size: 12px; font-weight: 600; }
.flag.on { color: var(--sev-critical); }
.flag.off { color: var(--fg-3); }
.chipline { display: flex; flex-wrap: wrap; gap: 6px; }
.count {
  margin-left: 8px; font-size: 12px; font-weight: 600; color: var(--fg-3);
  background: var(--bg-muted); border-radius: var(--r-circular); padding: 1px 8px;
}

/* --- callouts ----------------------------------------------------------- */
.callout {
  border-radius: var(--r-md); padding: 12px 14px; margin: 0 0 16px;
  border-left: 3px solid; font-size: 14px;
}
.callout.warn { background: var(--sev-medium-bg); border-color: var(--sev-medium);
                color: var(--fg-1); }

/* --- tables ------------------------------------------------------------- */
.grid-wrap { overflow-x: auto; border: 1px solid var(--stroke-2);
             border-radius: var(--r-lg); margin-bottom: 16px; }
table.grid { border-collapse: collapse; width: 100%; font-size: 13px; }
table.grid th {
  text-align: left; font-size: 12px; line-height: 16px; font-weight: 600;
  color: var(--fg-3); text-transform: uppercase; letter-spacing: .04em;
  padding: 10px 12px; background: var(--bg-subtle);
  border-bottom: 1px solid var(--stroke-1); position: sticky; top: 0;
}
table.grid td { padding: 10px 12px; border-bottom: 1px solid var(--stroke-2);
                vertical-align: top; color: var(--fg-2); }
table.grid tr:last-child td { border-bottom: 0; }
table.grid tbody tr:hover { background: var(--bg-subtle); }

code {
  font-family: var(--mono); font-size: 12px; background: var(--bg-muted);
  padding: 1px 5px; border-radius: var(--r-md); color: var(--fg-1);
}
code.snippet { display: block; max-width: 56ch; white-space: pre-wrap;
               word-break: break-word; color: var(--fg-3); background: transparent;
               padding: 0; }

/* --- findings ----------------------------------------------------------- */
.sev-heading { display: flex; align-items: center; font-size: 16px; margin: 28px 0 12px;
               padding-bottom: 6px; border-bottom: 2px solid currentColor; }
.sev-heading.sev-critical { color: var(--sev-critical); }
.sev-heading.sev-high     { color: var(--sev-high); }
.sev-heading.sev-medium   { color: var(--sev-medium); }
.sev-heading.sev-low      { color: var(--sev-low); }
.sev-heading.sev-info     { color: var(--sev-info); }
.finding {
  border: 1px solid var(--stroke-2); border-left: 3px solid; border-radius: var(--r-lg);
  padding: 14px 16px; margin-bottom: 10px; background: var(--bg-subtle);
}
.finding.sev-critical { border-left-color: var(--sev-critical); }
.finding.sev-high     { border-left-color: var(--sev-high); }
.finding.sev-medium   { border-left-color: var(--sev-medium); }
.finding.sev-low      { border-left-color: var(--sev-low); }
.finding.sev-info     { border-left-color: var(--sev-info); }
.finding-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
                margin-bottom: 6px; }
.finding-head h4 { margin: 0; font-size: 15px; color: var(--fg-1); }
.src { margin-left: auto; font-size: 12px; color: var(--fg-3); font-family: var(--mono); }
.finding-detail { margin: 0; font-size: 13px; line-height: 19px; }
.evidence { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px;
            margin: 10px 0 0; padding: 10px 0 0; border-top: 1px solid var(--stroke-2);
            font-size: 12px; }
.ev-row { display: contents; }
.evidence dt { font-weight: 600; color: var(--fg-3); font-family: var(--mono); }
.evidence dd { margin: 0; color: var(--fg-2); word-break: break-word; }

/* --- reference disclosure ------------------------------------------------ */
details.ref { border: 1px solid var(--stroke-2); border-radius: var(--r-lg);
              margin-bottom: 8px; background: var(--bg-subtle); }
details.ref > summary {
  cursor: pointer; padding: 10px 14px; font-weight: 600; list-style: none;
  display: flex; align-items: center; gap: 8px;
}
details.ref > summary::-webkit-details-marker { display: none; }
details.ref > summary::before { content: "\\25B8" / ""; color: var(--fg-3); }
details.ref[open] > summary::before { content: "\\25BE" / ""; }
details.ref[open] > summary { border-bottom: 1px solid var(--stroke-2); }
details.ref .grid-wrap { border: 0; margin: 0; border-radius: 0; }
details.query > summary { cursor: pointer; font-size: 12px; color: var(--brand-80);
                         font-weight: 600; }
details.query pre {
  margin: 6px 0 0; padding: 10px 12px; max-width: 70ch; overflow-x: auto;
  background: var(--bg-muted); border-radius: var(--r-md);
  font-family: var(--mono); font-size: 12px; line-height: 17px;
  white-space: pre-wrap; word-break: break-word; color: var(--fg-1);
}

@media print {
  .tabs { display: none; }
  .panel[hidden] { display: block !important; }
  .hero { background: #f3f3f3 !important; -webkit-print-color-adjust: exact;
          print-color-adjust: exact; }
  .hero::after { display: none; }
  .card { break-inside: avoid; box-shadow: none; }
  details.ref[open] { break-inside: avoid; }
  details.ref:not([open]) > summary::before { content: "\\25B8" / ""; }
}
@media (max-width: 720px) {
  .hero { padding: 20px 16px 18px; }
  .hero h1 { font-size: 22px; line-height: 28px; }
  .hero-verdict { padding: 6px 12px; }
  main { padding: 16px; }
  .card { padding: 16px; }
  .tabs { padding: 0 8px; }
  .evidence { grid-template-columns: 1fr; }
}
"""

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Power Pages exposure audit</title>
<style>{styles}</style>
</head><body>
{header}
{tabs}
<main>
{body}
</main>
<script>{script}</script>
</body></html>"""
