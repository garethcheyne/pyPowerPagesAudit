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
from typing import Any, Iterable

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


# --- sections ----------------------------------------------------------------


def _header(report: Report) -> str:
    ctx = report.context
    meta = []
    if ctx.get("portal_url"):
        meta.append(("Portal", f'<a href="{_esc(ctx["portal_url"])}" target="_blank" '
                               f'rel="noopener noreferrer">{_esc(ctx["portal_url"])}</a>'))
    if ctx.get("dataverse_url"):
        meta.append(("Dataverse", _code(ctx["dataverse_url"])))
    if not meta:
        meta.append(("Target", _code(report.target)))
    meta.append(("Run (UTC)", _esc(report.started)))
    if ctx.get("whoami"):
        meta.append(("Audited as", _code(ctx["whoami"])))
    generations = ctx.get("config_generations", [])
    if generations:
        meta.append(("Configuration model",
                     ", ".join(f'{_esc(g["label"])} <code>{_esc(g["generation"])}_*</code>'
                               for g in generations)))
    if ctx.get("content_sources_scanned"):
        meta.append(("Content sources scanned", _esc(ctx["content_sources_scanned"])))

    items = "".join(f'<div class="meta-item"><dt>{_esc(k)}</dt><dd>{v}</dd></div>'
                    for k, v in meta)
    instance = ctx.get("instance") or "Power Pages exposure audit"
    return f"""
<header class="hero">
  <div class="hero-inner">
    <div class="eyebrow">Power Pages &middot; Dataverse exposure audit</div>
    <h1>{_esc(instance)}</h1>
    <p class="lede">What an unauthenticated visitor can reach through this site,
       and the configuration that allows it.</p>
    <dl class="meta">{items}</dl>
  </div>
</header>"""


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
    items = "".join(
        f'<li>{_badge(f.severity)} <span class="act-title">{_esc(f.title)}</span>'
        f'{" " + _code(f.table) if f.table else ""}</li>'
        for f in actionable) or '<li class="empty">Nothing at Medium or above.</li>'
    return f"""
<section id="summary" class="card">
  <h2>Summary</h2>
  <div class="stats">{"".join(cards)}</div>
  <h3>Requiring action</h3>
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
            where = _esc(f"{ref.kind} — {ref.source_name}")
            if ref.url:
                where = (f'<a href="{_esc(ref.url)}" target="_blank" rel="noopener '
                         f'noreferrer">{where}</a>')
            rows.append([
                where,
                f'<span class="muted">{_esc(ref.how)}</span>',
                f'<span class="muted">line {ref.line}</span>',
                " ".join(_code(c) for c in ref.columns) or '<span class="muted">—</span>',
                f'<code class="snippet">{_esc(ref.snippet)}</code>',
            ])
        blocks.append(
            f'<details class="ref"><summary><code>{_esc(table)}</code>'
            f'<span class="count">{len(populated[table])} reference(s)</span></summary>'
            + _table(["Where", "How", "Line", "Columns", "Source excerpt"], rows, "none")
            + "</details>")
    return f"""
<section id="rendered" class="card">
  <h2>Where the data is rendered</h2>
  <p>Found by scanning the site's Liquid web templates, web page copy and scripts,
     content snippets and entity list FetchXML. Open the URL to see what the page
     actually returns — where the Web API is off, the page is the only channel, so
     the page is what bounds the exposure.</p>
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
            if f.evidence:
                evidence = "".join(
                    f'<div class="ev-row"><dt>{_esc(k)}</dt>'
                    f'<dd>{_linkify(str(v))}</dd></div>'
                    for k, v in f.evidence.items())
                evidence = f'<dl class="evidence">{evidence}</dl>'
            detail = _linkify(f.detail).replace("\n", "<br>") if f.detail else ""
            cards.append(
                f'<article class="finding {_sev_class(severity)}">'
                f'<div class="finding-head">{_badge(severity)}'
                f'<h4>{_esc(f.title)}</h4>'
                f'{_code(f.table)}'
                f'<span class="src">{_esc(f.source)}</span></div>'
                f'<p class="finding-detail">{detail}</p>{evidence}</article>')
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


def render(report: Report) -> str:
    nav = [("summary", "Summary"), ("anonymous", "Anonymous access"),
           ("external", "External scan"), ("rendered", "Where rendered"),
           ("findings", "Findings"), ("configuration", "Configuration")]
    body = "".join([
        _summary(report), _anonymous(report), _external(report),
        _references(report), _findings(report), _configuration(report),
    ])
    present = [(anchor, label) for anchor, label in nav if f'id="{anchor}"' in body]
    links = "".join(f'<a href="#{a}">{_esc(l)}</a>' for a, l in present)
    return _TEMPLATE.format(
        title=_esc(report.context.get("instance") or "Power Pages exposure audit"),
        header=_header(report),
        nav=f'<nav class="toc">{links}</nav>' if links else "",
        body=body,
        styles=_STYLES,
    )


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

/* --- hero: Power Platform maker-portal masthead ------------------------- */
.hero {
  background:
    radial-gradient(1200px 400px at 12% -40%, rgba(71,158,245,.45), transparent 60%),
    linear-gradient(120deg, #0b2a4a 0%, #115ea3 45%, #7a3fa8 100%);
  color: #fff; padding: 40px 32px 32px;
}
.hero-inner { max-width: none; margin: 0; }
.eyebrow {
  text-transform: uppercase; letter-spacing: .08em; font-size: 12px;
  font-weight: 600; opacity: .82; margin-bottom: 8px;
}
.hero h1 {
  font-family: var(--font-display); font-size: 32px; line-height: 40px;
  font-weight: 600; margin: 0 0 6px;
}
.lede { margin: 0 0 20px; font-size: 16px; line-height: 22px; opacity: .9; max-width: 70ch; }
.meta { display: flex; flex-wrap: wrap; gap: 10px 28px; margin: 0; }
.meta-item dt {
  font-size: 12px; line-height: 16px; text-transform: uppercase;
  letter-spacing: .04em; opacity: .75; font-weight: 600;
}
.meta-item dd { margin: 2px 0 0; font-size: 14px; }
.meta a, .meta code { color: #fff; }
.meta code { background: rgba(255,255,255,.16); }

/* --- nav ---------------------------------------------------------------- */
.toc {
  position: sticky; top: 0; z-index: 5;
  background: var(--bg-surface); border-bottom: 1px solid var(--stroke-2);
  padding: 0 32px; display: flex; gap: 4px; overflow-x: auto;
  box-shadow: var(--shadow-2);
}
.toc a {
  padding: 12px 14px; font-size: 14px; font-weight: 600; color: var(--fg-2);
  border-bottom: 2px solid transparent; white-space: nowrap;
}
.toc a:hover { color: var(--brand-80); border-bottom-color: var(--stroke-1); text-decoration: none; }

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
details.ref > summary::before { content: "\\25B8"; color: var(--fg-3); }
details.ref[open] > summary::before { content: "\\25BE"; }
details.ref[open] > summary { border-bottom: 1px solid var(--stroke-2); }
details.ref .grid-wrap { border: 0; margin: 0; border-radius: 0; }

@media print {
  .toc { display: none; }
  .hero { background: #115ea3 !important; -webkit-print-color-adjust: exact;
          print-color-adjust: exact; }
  .card { break-inside: avoid; box-shadow: none; }
  details.ref[open] { break-inside: avoid; }
  details.ref:not([open]) > summary::before { content: "\\25B8"; }
}
@media (max-width: 720px) {
  .hero { padding: 28px 20px 24px; }
  .hero h1 { font-size: 24px; line-height: 32px; }
  main { padding: 16px; }
  .card { padding: 16px; }
  .toc { padding: 0 16px; }
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
{nav}
<main>
{body}
</main>
</body></html>"""
