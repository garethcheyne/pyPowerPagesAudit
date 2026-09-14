"""Markdown renderer for the Power Pages exposure audit.

The HTML and console renderers list findings. This one produces a *review
document*: the configuration a reviewer needs to see, laid out so they can
check it against intent — web roles, table permissions, column permissions and
their profiles, Web API site settings, OData feeds, page access rules — with
the anonymous surface called out first and the findings supporting it.

It is written to be read top-down by someone who did not run the tool.
"""

from __future__ import annotations

from typing import Any, Iterable

from .report import Report, Severity

CHECK = "yes"
CROSS = "no"


def _esc(value: Any) -> str:
    """Escape pipes and newlines so a value cannot break out of a table cell."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _table(headers: list[str], rows: Iterable[list[Any]], empty: str) -> list[str]:
    rows = [r for r in rows]
    if not rows:
        return [f"_{empty}_", ""]
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_esc(c) for c in row) + " |" for row in rows]
    out.append("")
    return out


def _bool(value: bool) -> str:
    return CHECK if value else CROSS


def _mdlink(text: Any, url: str) -> str:
    """Markdown link when the record URL resolved, plain text when it did not.

    Left unescaped on purpose: ``_table`` escapes every cell afterwards, and
    escaping here as well would double up the backslashes on names containing a
    pipe.
    """
    label = "" if text is None else str(text)
    return f"[{label}]({url})" if url else label


def render(report: Report) -> str:
    lines: list[str] = []
    lines += _header(report)

    section = _Counter()
    lines += _summary(report, section.next())
    lines += _anonymous_surface(report, section.next())
    scan = _external_scan(report, section.peek())
    if scan:
        section.next()
        lines += scan
    rendered = _rendered(report, section.peek())
    if rendered:
        section.next()
        lines += rendered
    for model in getattr(report, "models", []) or []:
        if not getattr(model, "in_use", True):
            continue
        lines += _model_sections(model, section.next())
    lines += _findings(report, section.next())
    lines += _reference(section.next())
    return "\n".join(lines).rstrip() + "\n"


class _Counter:
    def __init__(self) -> None:
        self.value = 0

    def next(self) -> int:
        self.value += 1
        return self.value

    def peek(self) -> int:
        return self.value + 1


# --- sections ----------------------------------------------------------------


def _header(report: Report) -> list[str]:
    context = report.context
    generations = context.get("config_generations", [])
    lines = [
        "# Power Pages exposure audit",
        "",
    ]
    if context.get("instance"):
        lines.append(f"**Environment:** {context['instance']}  ")
    if context.get("portal_url"):
        lines.append(f"**Portal:** `{context['portal_url']}`  ")
    if context.get("dataverse_url"):
        lines.append(f"**Dataverse:** `{context['dataverse_url']}`  ")
    if not (context.get("portal_url") or context.get("dataverse_url")):
        lines.append(f"**Target:** `{report.target}`  ")
    lines.append(f"**Run (UTC):** {report.started}  ")
    if context.get("whoami"):
        lines.append(f"**Audited as:** Dataverse user `{context['whoami']}`  ")
    if context.get("portal_version"):
        lines.append(f"**Power Pages version:** `{context['portal_version']}` "
                     "(MicrosoftPortalBase)  ")
    if generations:
        labels = ", ".join(f"{g['label']} (`{g['generation']}_*`)" for g in generations)
        lines.append(f"**Configuration model(s) detected:** {labels}  ")
    else:
        lines.append("**Configuration model(s) detected:** none — "
                     "no authenticated Dataverse audit ran  ")
    lines += ["", "> Authorised security assessment. This document describes the "
                  "configuration that governs public access to Dataverse data through "
                  "the Power Pages site named above.", ""]
    return lines


def _summary(report: Report, n: int) -> list[str]:
    counts = report.counts()
    lines = [f"## {n}. Executive summary", ""]
    lines += _table(
        ["Severity", "Findings", "What it means"],
        [[s.label, counts[s.label], _severity_meaning(s)]
         for s in reversed(Severity) if counts[s.label]],
        "No findings were recorded.")

    critical = [f for f in report.sorted() if f.severity >= Severity.HIGH]
    if critical:
        lines += ["### Issues requiring action", ""]
        for finding in critical[:15]:
            where = f" — `{finding.table}`" if finding.table else ""
            lines.append(f"- **[{finding.severity.label}]** {finding.title}{where}")
        if len(critical) > 15:
            lines.append(f"- _…and {len(critical) - 15} more; see the findings section._")
        lines.append("")
    else:
        lines += ["No High or Critical findings were raised.", ""]

    generations = report.context.get("config_generations", [])
    if generations:
        lines += ["### Configuration inventory", ""]
        lines += _table(
            ["Model", "Websites", "Web roles", "Table permissions",
             "Column permission profiles", "Web API tables enabled"],
            [[g["label"], ", ".join(g["websites"]) or "(none)", g["web_roles"],
              g["table_permissions"], g["column_permission_profiles"],
              g["webapi_tables_enabled"]] for g in generations],
            "No configuration was read.")
    return lines


def _severity_meaning(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "Data is exposed to the public internet, or anonymous users can modify data. Fix now.",
        Severity.HIGH: "Exposure is proven or near-certain. Fix in this cycle.",
        Severity.MEDIUM: "Weakens the security posture or makes exposure likely under a small change.",
        Severity.LOW: "Hygiene and least-privilege issues; review and tidy.",
        Severity.INFO: "Context recorded so the reviewer can verify intent.",
    }[severity]


def _anonymous_surface(report: Report, n: int) -> list[str]:
    """The headline: what an unauthenticated visitor can reach, and why."""
    matrix = getattr(report, "access_matrix", []) or []
    anon = [a for a in matrix if a.anonymous]
    lines = [f"## {n}. Anonymous access", "",
             "Everything bound to a web role flagged as the **Anonymous Users role** is "
             "reachable by anyone on the internet, with no sign-in. `Global` scope means "
             "every row in the table; `Contact`/`Account`/`Parent`/`Self` scope resolves "
             "against the signed-in contact, which an anonymous visitor does not have.",
             ""]
    if not anon:
        lines += ["_No table permission is bound to an anonymous web role in the "
                  "configuration that was read._", ""]
    else:
        lines += _table(
            ["Table", "Permission", "Scope", "Privileges", "Web API",
             "Published fields", "Column profile", "Columns reachable"],
            [[f"`{a.table}`", _mdlink(a.permission, a.config_url), a.scope,
              ", ".join(a.privileges) or "(none)",
              _bool(a.webapi_enabled), a.webapi_fields,
              ", ".join(a.column_profiles) or "(none)", a.readable_columns]
             for a in sorted(anon, key=lambda x: (x.table.lower(), x.permission.lower()))],
            "none")
        flagged = sorted({c for a in anon for c in a.sensitive_columns})
        if flagged:
            lines += ["**Columns matching personal-data patterns reachable anonymously:**",
                      "", ", ".join(f"`{c}`" for c in flagged), ""]

    auth = [a for a in matrix if a.authenticated]
    lines += ["### Authenticated Users role", "",
              "Anything granted to the Authenticated Users role is available to every "
              "signed-in contact. Where self-registration is open, that is effectively "
              "the public as well.", ""]
    dual = sorted({a.role for a in auth if a.anonymous})
    if dual:
        lines += [f"> These rows come from {', '.join(f'`{r}`' for r in dual)}, which "
                  "carries the Anonymous **and** Authenticated Users role flags, so the "
                  "two audiences are the same set of permissions. See the finding "
                  "*One web role serves both anonymous and signed-in users*.", ""]
    lines += _table(
        ["Table", "Permission", "Scope", "Privileges", "Web API", "Columns reachable"],
        [[f"`{a.table}`", a.permission, a.scope, ", ".join(a.privileges) or "(none)",
          _bool(a.webapi_enabled), a.readable_columns]
         for a in sorted(auth, key=lambda x: (x.table.lower(), x.permission.lower()))],
        "No table permission is bound to an Authenticated Users role.")
    return lines


def _rendered(report: Report, n: int) -> list[str]:
    """Where the site actually renders each table, with both links to follow."""
    refs = getattr(report, "references", {}) or {}
    populated = {t: r for t, r in refs.items() if r}
    if not populated:
        return []
    lines = [f"## {n}. Where the data is rendered", "",
             "Found by scanning the site's Liquid web templates, web page copy and "
             "scripts, content snippets and entity list FetchXML. Where the Web API is "
             "off, a page is the only channel, so the page is what bounds the exposure "
             "— not the permission.", "",
             "**Portal** is the live page, to see what it actually returns. "
             "**Dataverse** is the record holding the Liquid or FetchXML, which is what "
             "you edit to change it. **Query bounds** is what the query does to limit "
             "its own result — with the Web API off a filtered query is usually "
             "publishing by design, while `visitor input` means the query is built from "
             "request parameters and the visitor steers it.", ""]
    for table in sorted(populated):
        lines += [f"### `{table}`", ""]
        lines += _table(
            ["Source", "Portal", "Dataverse", "How", "Line", "Query bounds", "Columns"],
            [[f"{r.kind} — {r.source_name}",
              _mdlink("View page", r.url) or "—",
              _mdlink("Edit record", r.config_url) or "—",
              r.how, r.line,
              ("**visitor input**" if r.visitor_input
               else ", ".join(r.constraints) or "unfiltered"),
              ", ".join(f"`{c}`" for c in r.columns) or "—"]
             for r in populated[table]],
            "none")
        for ref in populated[table]:
            if not ref.block:
                continue
            lines += [f"<details><summary>Query — {_esc(ref.source_name)} "
                      f"(line {ref.line})</summary>", "", "```xml", ref.block,
                      "```", "", "</details>", ""]
    return lines


def _external_scan(report: Report, n: int) -> list[str]:
    context = report.context
    exposed = context.get("anon_exposed_tables")
    if exposed is None and not context.get("discovered_tables"):
        return []
    lines = [f"## {n}. External scan (unauthenticated, outside-in)", "",
             "Result of probing the live site with no credentials. This is proof, not "
             "inference: anything listed here was actually returned to an anonymous "
             "caller at scan time.", ""]
    lines += _table(
        ["Metric", "Value"],
        [["Tables probed", len(context.get("discovered_tables", []))],
         ["Tables that returned data anonymously", len(exposed or [])]],
        "No scan was run.")
    if exposed:
        lines += ["**Tables read anonymously:**", "",
                  ", ".join(f"`{t}`" for t in exposed), ""]
    scan_findings = [f for f in report.sorted() if f.source.startswith("anon")]
    if scan_findings:
        lines += _table(
            ["Severity", "Finding", "Table", "Evidence"],
            [[f.severity.label, f.title, f"`{f.table}`" if f.table else "—",
              _evidence_inline(f.evidence)] for f in scan_findings],
            "No scan findings.")
    return lines


def _model_sections(model, n: int) -> list[str]:
    """Per-generation configuration detail."""
    lines = [f"## {n}. Configuration detail — {model.label} (`{model.generation}_*`)", "",
             model.description, ""]
    if model.errors:
        lines += ["> **Incomplete.** The following configuration tables could not be "
                  "read, so this section is partial:", ""]
        lines += [f"> - `{name}` — {_esc(err)[:200]}" for name, err in model.errors.items()]
        lines.append("")

    lines += ["### Websites", ""]
    lines += _table(["Website", "Id"],
                    [[_mdlink(w.name, model.record_url("website", w.id)), f"`{w.id}`"]
                     for w in model.websites],
                    "No website records were readable.")

    lines += ["### Web roles", "",
              "`Anonymous Users role` is the public internet. `Authenticated Users role` "
              "applies to every signed-in contact. Named roles apply only where assigned. "
              "Record names link to the configuration record in Dataverse.",
              ""]
    lines += _table(
        ["Web role", "Type", "Website", "Table permissions", "Column profiles",
         "Page rules"],
        [[_mdlink(r.name, model.record_url("webrole", r.id)), r.kind,
          model.website_name(r.website_id),
          len(model.permissions_for_role(r.name)),
          sum(1 for p in model.profiles if r.name in p.roles),
          sum(1 for g in model.page_rules if r.name in g.roles)]
         for r in sorted(model.roles,
                         key=lambda x: (not x.is_anonymous, not x.is_authenticated,
                                        x.name.lower()))],
        "No web roles were readable.")

    lines += ["### Table permissions", "",
              "Each record grants privileges on one table to the web roles bound to it, "
              "limited by its access type (scope).", ""]
    lines += _table(
        ["Table", "Permission", "Scope", "Privileges", "Web roles", "Website", "Web API"],
        [[f"`{p.table}`",
          _mdlink(p.name, model.record_url("entitypermission", p.id)),
          p.scope or "(unset)",
          ", ".join(p.privileges()) or "(none)",
          ", ".join(p.roles) or "**(unbound)**",
          model.website_name(p.website_id),
          _bool(bool(model.webapi_for(p.table) and model.webapi_for(p.table).enabled))]
         for p in sorted(model.permissions,
                         key=lambda x: (x.table.lower(), x.name.lower()))],
        "No table permissions were readable.")

    lines += ["### Column permissions", "",
              "Column permission profiles narrow a table permission to named columns, for "
              "the web roles the profile is bound to. They apply to the Power Pages Web "
              "API only. Where no profile is bound, every column published by "
              "`Webapi/<table>/fields` is available to any role holding the table "
              "permission.", ""]
    lines += _table(
        ["Profile", "Table", "Web roles", "All-column permissions", "Explicit columns"],
        [[_mdlink(p.name, model.record_url("columnpermissionprofile", p.id)),
          f"`{p.table}`", ", ".join(p.roles) or "**(unbound)**",
          ", ".join(p.all_permissions) or "(none)", len(p.columns)]
         for p in sorted(model.profiles, key=lambda x: (x.table.lower(), x.name.lower()))],
        "No column permission profiles are configured. Column-level restriction is not "
        "in use, so table permissions apply to every published column.")

    column_rows = [
        [profile.name, f"`{profile.table}`", f"`{col.column}`",
         ", ".join(col.permissions) or "(none)",
         ", ".join(profile.roles) or "(unbound)"]
        for profile in model.profiles for col in profile.columns]
    if column_rows:
        lines += ["#### Per-column grants", ""]
        lines += _table(["Profile", "Table", "Column", "Permissions", "Web roles"],
                        sorted(column_rows, key=lambda r: (r[1], r[2])),
                        "none")

    lines += ["### Web API site settings", "",
              "`Webapi/<table>/enabled` switches the `/_api/<table>` endpoint on; "
              "`Webapi/<table>/fields` lists the columns it publishes. `*` publishes every "
              "column, including any added later.", ""]
    lines += _table(
        ["Table", "Enabled", "Published fields", "Roles with a table permission",
         "Column profiles", "Setting"],
        [[f"`{w.entity}`", _bool(w.enabled), w.fields_raw or "*",
          ", ".join(sorted({r for p in model.permissions
                            if p.table.lower() == w.entity.lower() for r in p.roles}))
          or "(none)",
          ", ".join(p.name for p in model.profiles_for(w.entity)) or "(none)",
          " ".join(filter(None, [
              _mdlink("enabled", model.record_url("sitesetting", w.enabled_setting_id))
              if w.enabled_setting_id else "",
              _mdlink("fields", model.record_url("sitesetting", w.fields_setting_id))
              if w.fields_setting_id else ""])) or "(none)"]
         for w in model.webapi],
        "No Webapi/* site settings exist, so the Web API publishes nothing.")

    feeds = [e for e in model.entity_lists if e.odata_enabled]
    lines += ["### OData feeds (entity lists)", "",
              "An entity list with the OData feed enabled serves data through "
              "`/_odata/...`, a separate channel from the Web API with its own exposure.",
              ""]
    lines += _table(
        ["Entity list", "Table", "OData entity set", "Fields", "Website"],
        [[_mdlink(e.name, model.record_url("entitylist", e.id)), f"`{e.table}`",
          e.odata_entityset or "(default)",
          e.odata_fields or "(view columns)", model.website_name(e.website_id)]
         for e in feeds],
        "No entity list has the OData feed enabled.")

    lines += ["### Web page access rules", "",
              "Page rules decide which roles can see or change a page. A page with no "
              "restricting rule is public.", ""]
    lines += _table(
        ["Page", "Rule", "Right", "Scope", "Web roles"],
        [[r.page_name, r.name, r.right or "(unset)", r.scope or "(unset)",
          ", ".join(r.roles) or "(none)"]
         for r in sorted(model.page_rules, key=lambda x: x.page_name.lower())],
        "No web page access control rules are configured; page-level restriction is not "
        "in use.")

    security_settings = model.security_settings()
    lines += ["### Security-relevant site settings", ""]
    lines += _table(
        ["Setting", "Value", "Website"],
        [[f"`{s.name}`", s.value or "(empty)", model.website_name(s.website_id)]
         for s in sorted(security_settings, key=lambda x: x.name.lower())
         if not s.name.lower().startswith("webapi/")],
        "No authentication, header, tracing or search settings were readable.")
    return lines


def _findings(report: Report, n: int) -> list[str]:
    lines = [f"## {n}. All findings", ""]
    current = None
    for finding in report.sorted():
        if finding.severity != current:
            current = finding.severity
            lines += [f"### {current.label}", ""]
        where = f" — `{finding.table}`" if finding.table else ""
        lines.append(f"#### {finding.title}{where}")
        lines.append("")
        if finding.detail:
            for paragraph in finding.detail.split("\n"):
                if paragraph.strip():
                    lines += [paragraph.strip(), ""]
        if finding.source:
            lines += [f"_Source: `{finding.source}`_", ""]
        if finding.evidence:
            query = str(finding.evidence.get("query") or "")
            rows = [[k, v] for k, v in finding.evidence.items() if k != "query"]
            if rows:
                lines += _table(["Evidence", "Value"], rows, "none")
            if query:
                lines += ["**Query as written** — judge whether it bounds the result:",
                          "", "```xml", query, "```", ""]
    if current is None:
        lines += ["_No findings._", ""]
    return lines


def _reference(n: int) -> list[str]:
    return [
        f"## {n}. How exposure works (reference for reviewers)",
        "",
        "For an anonymous visitor to read a Dataverse row through Power Pages, all of "
        "the following must line up:",
        "",
        "1. **A channel serves the table** — the Web API "
        "(`Webapi/<table>/enabled = true`, queried at `/_api/<table>`), an entity list "
        "with the OData feed enabled (`/_odata/<set>`), an entity form, or a Liquid "
        "`fetchxml` / `entityview` tag on a page.",
        "2. **A table permission grants `Read`** on that table.",
        "3. **That permission is bound to a web role flagged as the Anonymous Users "
        "role.**",
        "4. **Scope is `Global`.** Global means all rows. "
        "`Contact` / `Account` / `Parent` / `Self` resolve against the signed-in "
        "contact, which an anonymous visitor does not have — so those normally return "
        "nothing, though scope misuse is a common misconfiguration and they still "
        "warrant review.",
        "",
        "Column reach is then decided by, in order: the table permission (does the role "
        "get the table at all), `Webapi/<table>/fields` (which columns the Web API "
        "publishes — `*` means all, including columns added later), and column "
        "permission profiles bound to the role (which narrow it further). Column "
        "permissions apply to the Web API only, and are **not** enforced on sites using "
        "the enhanced authorization model — those use column security profiles instead.",
        "",
        "Two configuration models exist and either can grant access: the **standard "
        "data model** (`adx_*` physical tables) and the **enhanced data model** "
        "(`mspp_*` virtual tables over `powerpagesite` / `powerpagecomponent`). "
        "Environments upgraded in place often carry both, and permissions left behind "
        "in the other model are easy to miss.",
        "",
        "### Review checklist",
        "",
        "- [ ] Every table permission bound to an anonymous role is intended, and its "
        "scope is deliberate.",
        "- [ ] No anonymous role has `Write`, `Create` or `Delete` anywhere.",
        "- [ ] Every `Webapi/<table>/fields` setting lists explicit columns rather "
        "than `*`.",
        "- [ ] Tables carrying personal data have a column permission profile, or an "
        "explicit field list, that excludes sensitive columns.",
        "- [ ] Entity lists with the OData feed enabled sit on access-controlled pages.",
        "- [ ] Table permissions bound to no web role are removed, not left dormant.",
        "- [ ] Self-registration settings match intent, given what the Authenticated "
        "Users role can reach.",
        "- [ ] If both configuration models are present, they agree.",
        "",
    ]


def _evidence_inline(evidence: dict[str, Any]) -> str:
    if not evidence:
        return "—"
    return "; ".join(f"{k}={v}" for k, v in evidence.items())
