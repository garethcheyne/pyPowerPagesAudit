"""Inside-out Dataverse permission analysis and correlation.

:mod:`ppaudit.model` reads the configuration; this module decides what it
*means*. It walks every configuration generation present (standard ``adx_``
and enhanced ``mspp_``) and answers, per web role and per table:

* can this role read the table at all, and over what scope;
* is the Web API switched on for it, and which columns does
  ``Webapi/<entity>/fields`` publish;
* do column permission profiles narrow that, or is every published column
  readable;
* is the role the **Anonymous Users** role — i.e. is this the public internet.

The headline check is deliberate: a table permission granting **Read with
Global scope bound to the Anonymous Users role** hands the whole table to
anyone. Anonymous write/create/delete is critical regardless of scope.

Finally it reconciles the model against the anonymous scanner's observations,
so each externally-proven leak is tied to the configuration that causes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .constants import (
    NOTABLE_SETTINGS,
    PORTAL_CONTENT_TABLES,
    SCOPE_GLOBAL,
    SENSITIVE_COLUMN_HINTS,
    SENSITIVE_TABLES,
)
from .dataverse import DataverseClient, DataverseError
from .model import ConfigLoader, SchemaModel, TablePermission
from .references import ReferenceIndex
from .report import Finding, Report, Severity
from . import versions


def is_sensitive_column(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SENSITIVE_COLUMN_HINTS)


def is_sensitive_table(name: str) -> bool:
    return name.lower() in SENSITIVE_TABLES


def is_portal_content(name: str) -> bool:
    """True for CMS tables the site must read anonymously in order to render."""
    return name.lower() in PORTAL_CONTENT_TABLES


# Columns worth looking for in page content even when the Web API is off and so
# no published field list exists to drive the search.
SENSITIVE_COLUMN_SEEDS = [
    "emailaddress1", "telephone1", "mobilephone", "firstname", "lastname",
    "fullname", "address1_line1", "address1_postalcode", "birthdate",
    "parentcustomerid", "domainname", "internalemailaddress",
]


def _release_date(version: str) -> date | None:
    """``9.3.2509.0`` -> September 2025. Power Pages encodes YYMM in the build."""
    parts = version.split(".")
    if len(parts) < 3 or not parts[2].isdigit() or len(parts[2]) != 4:
        return None
    year, month = 2000 + int(parts[2][:2]), int(parts[2][2:])
    if not 1 <= month <= 12 or not 2015 <= year <= 2100:
        return None
    return date(year, month, 1)


def _months_since(released: date) -> int:
    today = date.today()
    return (today.year - released.year) * 12 + today.month - released.month


def _page_exposure_severity(webapi_open: bool, steerable: bool, constrained: bool,
                            sensitive: bool, risky: bool) -> tuple[Severity, str]:
    """Grade a page that renders anonymously-readable data.

    Configuration alone cannot make this Critical. With the Web API off, the
    page renders server-side: the visitor gets whatever the query emits and
    cannot ask for anything else. That is the supported way to publish data, so
    an unfiltered query is a prompt to read the Liquid, not evidence of a leak.

    Critical is reserved for the cases where the visitor can actually influence
    what comes back — a Web API endpoint, or a query built from request input.
    """
    if webapi_open:
        return (Severity.CRITICAL if sensitive else Severity.HIGH,
                "The Web API makes this directly queryable, so the permission is the "
                "only limit. Restrict the published columns or the permission.")

    if steerable:
        return (Severity.CRITICAL if sensitive else Severity.HIGH,
                "Because the query is built from request input, treat this as a "
                "queryable endpoint: check the parameter is validated and cannot be "
                "used to widen the result or inject conditions.")

    if constrained:
        return (Severity.LOW if sensitive else Severity.INFO,
                "This looks deliberate. Confirm the filter restricts on the right "
                "thing and cannot be satisfied by an anonymous visitor, then treat it "
                "as published-by-design.")

    return (Severity.MEDIUM if sensitive else Severity.LOW,
            "Read the Liquid and confirm what the query returns: if it is unfiltered "
            "and the table holds anything not meant to be public, add a filter, a page "
            "permission, or narrow the table permission. Server-side rendering bounds "
            "the columns but not the rows.")


def _anonymous_read_severity(table: str, channel: str, referenced: bool,
                             sensitive: list[str]) -> tuple[Severity, str]:
    """Grade an anonymous global read by what can actually be done with it.

    Read-only access to a table nothing queries and no page renders is not the
    same as a queryable endpoint over personal data, and grading them alike
    buries the second in noise.
    """
    risky = is_sensitive_table(table) or bool(sensitive)

    if channel == "proven":
        return (Severity.CRITICAL,
                "Confirmed exposure: fix the permission or the channel.")

    if channel == "queryable":
        if is_portal_content(table):
            return (Severity.LOW,
                    "This is portal content the site must publish in order to render, "
                    "but exposing it through a queryable endpoint still hands an "
                    "attacker the site's structure. Restrict the Web API to the "
                    "columns actually needed.")
        if risky:
            return (Severity.CRITICAL,
                    "A visitor can query every row of a table holding personal data. "
                    "Remove the Global scope or the anonymous binding now.")
        return (Severity.HIGH,
                "A visitor can enumerate the whole table at will. Confirm every row "
                "and column is intended to be public.")

    # render-only: bounded by the page, so the question is what the page shows.
    if is_portal_content(table):
        return (Severity.INFO,
                "This is portal content that the site reads anonymously in order to "
                "render pages, with no query channel open. Expected configuration.")
    if not referenced:
        return (Severity.LOW,
                "Nothing renders it and nothing can query it, so it is granting access "
                "no-one is using. Remove the permission to keep the anonymous role "
                "minimal.")
    if risky:
        return (Severity.HIGH,
                "A page renders this table anonymously and it holds personal data. "
                "Open the URL above and confirm exactly which rows and columns reach "
                "the page — Global scope means the template, not the permission, is "
                "the only thing limiting what is shown.")
    return (Severity.MEDIUM,
            "A page renders this table to anonymous visitors. Global scope means the "
            "permission imposes no limit, so review the page and its FetchXML to "
            "confirm the filtering is deliberate.")


@dataclass
class AccessEntry:
    """One role's effective reach into one table, via one permission."""

    generation: str
    website: str
    role: str
    role_kind: str
    anonymous: bool
    authenticated: bool
    table: str
    permission: str
    scope: str
    privileges: list[str] = field(default_factory=list)
    config_url: str = ""
    webapi_enabled: bool = False
    webapi_fields: str = ""
    column_profiles: list[str] = field(default_factory=list)
    readable_columns: str = ""
    sensitive_columns: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "website": self.website,
            "role": self.role,
            "role_kind": self.role_kind,
            "table": self.table,
            "permission": self.permission,
            "scope": self.scope,
            "privileges": self.privileges,
            "config_url": self.config_url,
            "webapi_enabled": self.webapi_enabled,
            "webapi_fields": self.webapi_fields,
            "column_profiles": self.column_profiles,
            "readable_columns": self.readable_columns,
            "sensitive_columns": self.sensitive_columns,
            "notes": self.notes,
        }


class DataverseAudit:
    def __init__(self, client: DataverseClient, *, website: str | None = None,
                 portal_url: str = "", check_versions: bool = True) -> None:
        self.client = client
        self.website_filter = (website or "").strip().lower()
        self.portal_url = portal_url
        self.check_versions = check_versions
        self.models: list[SchemaModel] = []
        self.access: list[AccessEntry] = []
        self.references: dict[str, list] = {}
        self._index: ReferenceIndex | None = None
        self._externally_seen: set[str] = set()

    # --- entry point ---------------------------------------------------------

    def run(self, report: Report) -> None:
        try:
            generations = self.client.detect_schemas()
        except DataverseError as exc:
            report.add(Finding(Severity.INFO, "Dataverse audit could not start",
                               detail=str(exc), source="dataverse"))
            return

        for gen, cfg in generations:
            model = ConfigLoader(self.client, gen, cfg).load()
            if self.website_filter:
                model = _filter_to_website(model, self.website_filter)
            self.models.append(model)

        active = [m for m in self.models if m.in_use]
        sources = [s for m in active for s in m.content_sources(self.portal_url)]
        self._index = ReferenceIndex(sources)
        self._externally_seen = {t.lower() for t in
                                 report.context.get("anon_exposed_tables", [])}
        report.context["content_sources_scanned"] = len(sources)

        report.models = self.models
        report.context["config_generations"] = [
            {"generation": m.generation, "label": m.label, "in_use": m.in_use,
             "websites": [w.name for w in m.websites],
             "web_roles": len(m.roles), "table_permissions": len(m.permissions),
             "column_permission_profiles": len(m.profiles),
             "webapi_tables_enabled": sum(1 for w in m.webapi if w.enabled)}
            for m in active]

        for model in self.models:
            if not model.in_use:
                report.add(Finding(
                    Severity.INFO, f"{model.label} not in use",
                    detail=(f"No websites, web roles or table permissions exist in the "
                            f"{model.label.lower()} ({model.generation}_*), so it grants "
                            "nothing and is excluded from the rest of this report."),
                    source=f"dataverse:{model.generation}"))

        if len(active) > 1:
            report.add(Finding(
                Severity.MEDIUM, "Both Power Pages configuration models are present",
                detail=("This environment exposes configuration in both the standard "
                        "data model (adx_*) and the enhanced data model (mspp_*). Either "
                        "set can grant access, so both must be reviewed and kept in step. "
                        "Divergence between them is a common source of unintentionally "
                        "retained permissions."),
                source="dataverse",
                evidence={"generations": ", ".join(m.label for m in active)}))

        for model in active:
            self._inventory(report, model)
            self._build_access(model)
            self._analyse_roles(report, model)
            self._analyse_permissions(report, model)
            self._analyse_column_permissions(report, model)
            self._analyse_webapi(report, model)
            self._analyse_entity_lists(report, model)
            self._analyse_page_exposure(report, model)
            self._analyse_forms(report, model)
            self._analyse_files(report, model)
            self._analyse_settings(report, model)

        report.access_matrix = self.access
        report.context["access_matrix"] = [a.to_dict() for a in self.access]
        report.context["dataverse_models"] = [m.to_dict() for m in active]
        self._analyse_solutions(report)
        report.references = self.references
        report.context["references"] = {
            table: [r.to_dict() for r in refs]
            for table, refs in sorted(self.references.items()) if refs}
        self._correlate(report)

    # --- inventory -----------------------------------------------------------

    def _inventory(self, report: Report, model: SchemaModel) -> None:
        report.add(Finding(
            Severity.INFO, f"{model.label} configuration read",
            detail=(f"{model.description}\n"
                    f"{len(model.websites)} website(s), {len(model.roles)} web role(s), "
                    f"{len(model.permissions)} table permission(s), "
                    f"{len(model.profiles)} column permission profile(s), "
                    f"{sum(1 for w in model.webapi if w.enabled)} Web API-enabled table(s), "
                    f"{len(model.entity_lists)} entity list(s), "
                    f"{len(model.page_rules)} page access rule(s)."),
            source=f"dataverse:{model.generation}",
            evidence={"websites": ", ".join(w.name for w in model.websites) or "(none)"}))
        for entity_set, err in model.errors.items():
            report.add(Finding(
                Severity.LOW, "Configuration table unreadable",
                table=entity_set,
                detail=(f"Could not read {entity_set}; that part of the model is missing "
                        f"from this report. {err}"),
                source=f"dataverse:{model.generation}"))

    # --- effective access matrix ---------------------------------------------

    def _build_access(self, model: SchemaModel) -> None:
        by_name = {r.name: r for r in model.roles}
        for perm in model.permissions:
            webapi = model.webapi_for(perm.table)
            for role_name in perm.roles or ["(no role bound)"]:
                role = by_name.get(role_name)
                profiles = [p for p in model.profiles_for(perm.table)
                            if role_name in p.roles]
                entry = AccessEntry(
                    generation=model.generation,
                    website=model.website_name(perm.website_id),
                    role=role_name,
                    role_kind=role.kind if role else "Unknown role",
                    anonymous=bool(role and role.is_anonymous),
                    authenticated=bool(role and role.is_authenticated),
                    table=perm.table,
                    permission=perm.name,
                    scope=perm.scope or "(unset)",
                    privileges=perm.privileges(),
                    config_url=model.record_url("entitypermission", perm.id),
                    webapi_enabled=bool(webapi and webapi.enabled),
                    webapi_fields=(webapi.fields_raw or "*") if webapi else "(no setting)",
                    column_profiles=[p.name for p in profiles])
                entry.readable_columns, entry.sensitive_columns = _resolve_columns(
                    perm, webapi, profiles)
                if not perm.roles:
                    entry.notes.append(
                        "Not bound to any web role, so it grants nothing today — but it "
                        "is live configuration one binding away from taking effect.")
                if perm.parent_id and perm.scope != SCOPE_GLOBAL:
                    entry.notes.append(
                        "Scope resolves through a parent table permission; review the "
                        "whole chain, not this record alone.")
                self.access.append(entry)

    # --- analysis ------------------------------------------------------------

    def _analyse_roles(self, report: Report, model: SchemaModel) -> None:
        anon = model.anonymous_roles()
        auth = model.authenticated_roles()
        src = f"dataverse:{model.generation}"
        if not anon:
            report.add(Finding(
                Severity.INFO, "No Anonymous Users role is defined",
                detail=("No web role is flagged as the Anonymous Users role in this "
                        "configuration model, so table permissions cannot be granted to "
                        "unauthenticated visitors through web roles."),
                source=src))
        if len(anon) > 1:
            report.add(Finding(
                Severity.MEDIUM, "Multiple Anonymous Users roles",
                detail=("More than one web role is flagged as the Anonymous Users role: "
                        f"{', '.join(r.name for r in anon)}. Every permission bound to any "
                        "of them applies to unauthenticated visitors, which makes the "
                        "public surface hard to reason about."),
                source=src))
        if len(auth) > 1:
            report.add(Finding(
                Severity.LOW, "Multiple Authenticated Users roles",
                detail=("More than one web role is flagged as the Authenticated Users "
                        f"role: {', '.join(r.name for r in auth)}. All of them apply to "
                        "every signed-in contact."),
                source=src))
        for role in anon:
            granted = model.permissions_for_role(role.name)
            report.add(Finding(
                Severity.INFO, "Anonymous Users role identified",
                detail=(f"Web role '{role.name}' is the Anonymous Users role for "
                        f"{model.website_name(role.website_id)}. Everything bound to it is "
                        "reachable by the public internet. It currently carries "
                        f"{len(granted)} table permission(s)."),
                source=src,
                evidence={"role": role.name, "table_permissions": len(granted)}))

        for role in [r for r in model.roles if r.is_anonymous and r.is_authenticated]:
            report.add(Finding(
                Severity.HIGH, "One web role serves both anonymous and signed-in users",
                detail=(f"Web role '{role.name}' has both the Anonymous Users role and "
                        "the Authenticated Users role flags set. Every permission intended "
                        "for signed-in contacts on this role is therefore also granted to "
                        "the public internet, and the two audiences can no longer be "
                        "separated without splitting the role. Clear one flag and move the "
                        "permissions to the audience they were meant for."),
                source=src,
                evidence={"role": role.name,
                          "table_permissions": len(model.permissions_for_role(role.name))}))

    def _analyse_permissions(self, report: Report, model: SchemaModel) -> None:
        src = f"dataverse:{model.generation}"
        anon_roles = model.role_names(lambda r: r.is_anonymous)
        auth_roles = model.role_names(lambda r: r.is_authenticated)
        open_registration = _setting_is(
            model, "Authentication/Registration/OpenRegistrationEnabled", "true")

        for perm in model.permissions:
            webapi = model.webapi_for(perm.table)
            on_anon = [r for r in perm.roles if r in anon_roles]
            on_auth = [r for r in perm.roles if r in auth_roles]
            site = model.website_name(perm.website_id)

            if on_anon:
                self._flag_anonymous_permission(
                    report, model, perm, on_anon, webapi, site, src)
            elif on_auth and open_registration:
                sev = Severity.HIGH if perm.scope == SCOPE_GLOBAL else Severity.MEDIUM
                report.add(Finding(
                    sev, "Authenticated-role access with open self-registration",
                    table=perm.table,
                    detail=(f"'{perm.name}' grants {', '.join(perm.privileges()) or 'no'} "
                            f"privileges with {perm.scope or 'unset'} scope to the "
                            f"Authenticated Users role ({', '.join(on_auth)}). Open "
                            "registration is enabled, so any member of the public can "
                            "create an account and inherit this access. Treat it as "
                            "near-public exposure."
                            + (" Global scope means every row in the table."
                               if perm.scope == SCOPE_GLOBAL else "")),
                    source=src,
                    evidence={"permission": perm.name, "scope": perm.scope,
                              "privileges": ", ".join(perm.privileges()),
                              "website": site,
                              "webapi_enabled": bool(webapi and webapi.enabled)}))

            if not perm.roles:
                report.add(Finding(
                    Severity.LOW, "Table permission bound to no web role",
                    table=perm.table,
                    detail=(f"'{perm.name}' ({perm.scope or 'unset'} scope, "
                            f"{', '.join(perm.privileges()) or 'no privileges'}) is not "
                            "bound to any web role. It grants nothing today, but it is "
                            "live configuration one binding away from taking effect. "
                            "Remove it or bind it deliberately."),
                    source=src, evidence={"website": site}))

            if not perm.scope:
                report.add(Finding(
                    Severity.MEDIUM, "Table permission has no access type set",
                    table=perm.table,
                    detail=(f"'{perm.name}' has no scope/access type configured. Scope is "
                            "what limits a permission to the signed-in contact's own rows; "
                            "without it the effective behaviour is ambiguous and must be "
                            "confirmed manually."),
                    source=src, evidence={"roles": ", ".join(perm.roles) or "(none)"}))

    def _channel(self, model: SchemaModel, table: str, webapi) -> tuple[str, str]:
        """How an anonymous visitor could reach the table, and what that permits.

        A permission alone exposes nothing. It needs a channel. Only the first
        two let the visitor choose their own query — the rest are bounded by
        whatever the page was built to show.
        """
        lowered = table.lower()
        if lowered in self._externally_seen:
            return ("proven", "The anonymous scanner already read this table from the "
                              "internet, so the exposure is confirmed, not theoretical.")
        if webapi and webapi.enabled:
            return ("queryable",
                    "The Web API is enabled for this table, so a visitor can compose "
                    f"their own query at /_api/{table}s with fields = "
                    f"{webapi.fields_raw or '*'} — filtering, paging and column "
                    "selection are all under their control, not the site's.")
        feeds = [e for e in model.entity_lists
                 if e.table.lower() == lowered and e.odata_enabled]
        if feeds:
            return ("queryable",
                    "An entity list publishes an OData feed for this table "
                    f"({', '.join(f.name for f in feeds)}), which is queryable directly.")
        return ("render-only",
                "The Web API is off and no OData feed is published, so a visitor cannot "
                "run their own query. The data is only reachable where a page renders "
                "it, so the real exposure is whatever those pages choose to show.")

    def _references_for(self, table: str, columns: list[str]):
        if self._index is None:
            return []
        if table not in self.references:
            self.references[table] = self._index.find(table, columns)
        return self.references[table]

    @staticmethod
    def _reference_note(refs) -> str:
        if not refs:
            return (" No Liquid template, page copy, entity list or page script in this "
                    "site was found to reference the table, so nothing appears to render "
                    "it today. Treat the permission as dormant configuration: it grants "
                    "access that only becomes live when someone adds a page that uses it.")
        urls = sorted({r.url for r in refs if r.url})
        where = "; ".join(sorted({f"{r.kind} '{r.source_name}'" for r in refs})[:4])
        note = f" Referenced by {where}"
        if len(refs) > 4:
            note += f" (+{len(refs) - 4} more)"
        note += "."
        if urls:
            note += " Inspect: " + ", ".join(urls[:5]) + ("…" if len(urls) > 5 else "")
        return note

    def _flag_anonymous_permission(self, report, model, perm: TablePermission,
                                   on_anon, webapi, site, src) -> None:
        mutating = perm.mutating
        if mutating:
            report.add(Finding(
                Severity.CRITICAL, "Anonymous data modification permitted",
                table=perm.table,
                detail=(f"Table permission '{perm.name}' grants {', '.join(mutating)} on "
                        f"'{perm.table}' to anonymous web role(s) {', '.join(on_anon)} "
                        f"with {perm.scope or 'unset'} scope. Unauthenticated visitors can "
                        "change or destroy data. Critical regardless of scope."),
                source=src,
                evidence={"permission": perm.name, "scope": perm.scope,
                          "privileges": ", ".join(perm.privileges()),
                          "roles": ", ".join(on_anon), "website": site,
                          "config_record": model.record_url("entitypermission", perm.id),
                          "webapi_enabled": bool(webapi and webapi.enabled)}))

        if not perm.read:
            return

        profiles = [p for p in model.profiles_for(perm.table)
                    if any(r in on_anon for r in p.roles)]
        columns, sensitive = _resolve_columns(perm, webapi, profiles)

        if perm.scope == SCOPE_GLOBAL:
            channel, channel_text = self._channel(model, perm.table, webapi)
            column_names = webapi.field_list if webapi else []
            refs = self._references_for(perm.table, column_names or SENSITIVE_COLUMN_SEEDS)
            severity, verdict = _anonymous_read_severity(
                perm.table, channel, bool(refs), sensitive)

            detail = (f"Table permission '{perm.name}' grants READ with GLOBAL scope on "
                      f"'{perm.table}' to anonymous web role(s) {', '.join(on_anon)}. "
                      "Global scope means every row, not just a signed-in contact's own "
                      f"records. {channel_text}{self._reference_note(refs)} {verdict}")
            detail += f" Columns reachable: {columns}."
            if sensitive:
                detail += (" Columns matching personal-data patterns are included: "
                           + ", ".join(sensitive) + ".")
            report.add(Finding(
                severity, "Anonymous global read of a table",
                table=perm.table, detail=detail, source=src,
                evidence={"permission": perm.name, "scope": perm.scope,
                          "roles": ", ".join(on_anon), "website": site,
                          "channel": channel,
                          "config_record": model.record_url("entitypermission", perm.id),
                          "webapi_enabled": bool(webapi and webapi.enabled),
                          "webapi_fields": (webapi.fields_raw or "*") if webapi else "(off)",
                          "rendered_at": ", ".join(sorted({r.url for r in refs if r.url})[:5])
                                         or "(no page reference found)",
                          "rendered_by_record": ", ".join(
                              sorted({r.config_url for r in refs if r.config_url})[:5])
                                         or "(none found)",
                          "referenced_by": "; ".join(
                              sorted({f"{r.kind}: {r.source_name}" for r in refs})[:5])
                                         or "(none found)",
                          "column_profiles": ", ".join(p.name for p in profiles) or "(none)",
                          "sensitive_columns": ", ".join(sensitive) or "(none detected)",
                          "sensitive_table": is_sensitive_table(perm.table)}))
        else:
            report.add(Finding(
                Severity.MEDIUM if is_sensitive_table(perm.table) else Severity.LOW,
                f"Anonymous read with {perm.scope or 'unset'} scope",
                table=perm.table,
                detail=(f"Table permission '{perm.name}' grants READ on '{perm.table}' to "
                        f"anonymous role(s) {', '.join(on_anon)} but with "
                        f"{perm.scope or 'unset'} scope. Scoped permissions resolve against "
                        "the signed-in contact or account, which an anonymous visitor does "
                        "not have, so this normally returns nothing. Review it anyway: "
                        "granting anything to the anonymous role is rarely intended, and "
                        "scope misuse is a common misconfiguration."),
                source=src,
                evidence={"permission": perm.name, "scope": perm.scope,
                          "roles": ", ".join(on_anon), "website": site,
                          "contact_relationship": perm.contact_relationship or "(none)",
                          "account_relationship": perm.account_relationship or "(none)"}))

    def _analyse_column_permissions(self, report: Report, model: SchemaModel) -> None:
        src = f"dataverse:{model.generation}"
        anon_roles = model.role_names(lambda r: r.is_anonymous)

        if model.generation == "mspp" and model.profiles:
            report.add(Finding(
                Severity.MEDIUM, "Column permissions may not be enforced on this site",
                detail=("Column permission profiles are configured, but column permissions "
                        "are not applied on sites running the enhanced authorization "
                        "model — column security profiles are used instead. Confirm which "
                        "authorization model this site uses: if it is enhanced, these "
                        "column restrictions are inert and every column allowed by the "
                        "table permission and the Webapi/<entity>/fields setting is "
                        "readable."),
                source=src, evidence={"profiles": len(model.profiles)}))

        for profile in model.profiles:
            on_anon = [r for r in profile.roles if r in anon_roles]
            reads = [c.column for c in profile.columns if "Read" in c.permissions]
            writes = [c.column for c in profile.columns
                      if {"Create", "Update"} & set(c.permissions)]
            sensitive = sorted({c for c in reads if is_sensitive_column(c)})

            if on_anon:
                mutable = bool(writes) or bool(
                    {"Create", "Update"} & set(profile.all_permissions))
                report.add(Finding(
                    Severity.CRITICAL if mutable else Severity.HIGH,
                    "Column permission profile bound to an anonymous role",
                    table=profile.table,
                    detail=(f"Column permission profile '{profile.name}' on "
                            f"'{profile.table}' is bound to anonymous web role(s) "
                            f"{', '.join(on_anon)}. All-column permissions: "
                            f"{', '.join(profile.all_permissions) or '(none)'}. Explicit "
                            f"column grants: {len(profile.columns)}."
                            + (f" Anonymous-writable columns: {', '.join(writes)}."
                               if writes else "")
                            + (" Personal-data columns readable anonymously: "
                               f"{', '.join(sensitive)}." if sensitive else "")),
                    source=src,
                    evidence={"profile": profile.name,
                              "roles": ", ".join(on_anon),
                              "all_column_permissions":
                                  ", ".join(profile.all_permissions) or "(none)",
                              "readable_columns":
                                  ", ".join(reads) or "(per all-column setting)",
                              "sensitive_columns":
                                  ", ".join(sensitive) or "(none detected)"}))
            elif not profile.roles:
                report.add(Finding(
                    Severity.LOW, "Column permission profile bound to no web role",
                    table=profile.table,
                    detail=(f"Profile '{profile.name}' on '{profile.table}' is not bound to "
                            "any web role, so it narrows nothing. Any role with a table "
                            "permission on this table reads every column the "
                            "Webapi/<entity>/fields setting publishes."),
                    source=src, evidence={"profile": profile.name}))

            if {"Create", "Update"} & set(profile.all_permissions):
                report.add(Finding(
                    Severity.LOW, "Profile grants Create/Update on all columns",
                    table=profile.table,
                    detail=(f"Profile '{profile.name}' sets All Column Permissions to "
                            f"{', '.join(profile.all_permissions)}, which applies to every "
                            "column not explicitly listed. Prefer explicit per-column "
                            "grants so new columns are not silently writable."),
                    source=src,
                    evidence={"profile": profile.name,
                              "roles": ", ".join(profile.roles) or "(none)"}))

    def _analyse_webapi(self, report: Report, model: SchemaModel) -> None:
        src = f"dataverse:{model.generation}"
        anon_roles = model.role_names(lambda r: r.is_anonymous)
        anon_global = {p.table.lower() for p in model.permissions
                       if p.read and p.scope == SCOPE_GLOBAL
                       and any(r in anon_roles for r in p.roles)}

        enabled = [w for w in model.webapi if w.enabled]
        if not enabled:
            report.add(Finding(
                Severity.INFO, "Web API is not enabled for any table",
                detail=("No Webapi/<entity>/enabled site setting is set to true in this "
                        "configuration model, so the /_api surface publishes nothing."),
                source=src))
            return

        for entry in enabled:
            if entry.entity.lower() in anon_global:
                continue  # already reported as a critical anonymous global read
            profiles = model.profiles_for(entry.entity)
            perms = [p for p in model.permissions
                     if p.table.lower() == entry.entity.lower()]
            roles_with = ", ".join(sorted({r for p in perms for r in p.roles})) or "(none)"
            unbound = ("" if perms else
                       " No table permission was found for this entity, so the endpoint "
                       "should return nothing — verify that externally.")

            if entry.all_fields:
                sev = Severity.HIGH if is_sensitive_table(entry.entity) else Severity.MEDIUM
                report.add(Finding(
                    sev, "Web API fields wildcard is deprecated",
                    table=entry.entity,
                    detail=(f"Webapi/{entry.entity}/enabled is true and "
                            f"Webapi/{entry.entity}/fields is "
                            f"{entry.fields_raw or 'unset'}, so every column of the "
                            "table is published to whichever roles hold a table "
                            "permission on it — including columns added later. "
                            "Microsoft deprecated the wildcard in the Power Pages "
                            "9.8.8.x release (August 2026): list the columns "
                            "explicitly, or set "
                            f"Webapi/{entry.entity}/UseFieldsFromView to true and "
                            "define a Dataverse view named 'Power Pages Web API "
                            "Columns'." + unbound),
                    source=src,
                    evidence={"roles_with_permission": roles_with,
                              "reference": "https://learn.microsoft.com/power-platform"
                                           "/released-versions/portals/pagesversion988x",
                              "column_profiles":
                                  ", ".join(p.name for p in profiles) or "(none)"}))
            else:
                sensitive = [c for c in entry.field_list if is_sensitive_column(c)]
                report.add(Finding(
                    Severity.INFO, "Web API enabled for table",
                    table=entry.entity,
                    detail=(f"Published columns: {', '.join(entry.field_list)}. Access is "
                            "governed by the table permissions on this entity." + unbound),
                    source=src,
                    evidence={"fields": len(entry.field_list),
                              "sensitive_columns":
                                  ", ".join(sensitive) or "(none detected)",
                              "roles_with_permission": roles_with,
                              "column_profiles":
                                  ", ".join(p.name for p in profiles) or "(none)"}))

    def _analyse_entity_lists(self, report: Report, model: SchemaModel) -> None:
        src = f"dataverse:{model.generation}"
        for entity_list in model.entity_lists:
            if not entity_list.odata_enabled:
                continue
            report.add(Finding(
                Severity.HIGH, "Entity list publishes an OData feed",
                table=entity_list.table,
                detail=(f"Entity list '{entity_list.name}' has the OData feed enabled, "
                        f"serving '{entity_list.table}' at "
                        f"/_odata/{entity_list.odata_entityset or entity_list.table}. The "
                        "OData feed is a separate channel from the Web API and is a "
                        "frequent cause of exposure that a Web API-only review misses. "
                        "Confirm the page hosting this list is access-controlled and the "
                        "underlying table permission is correctly scoped."),
                source=src,
                evidence={"entity_set": entity_list.odata_entityset or "(default)",
                          "fields": entity_list.odata_fields or "(view columns)",
                          "website": model.website_name(entity_list.website_id)}))

    def _analyse_page_exposure(self, report: Report, model: SchemaModel) -> None:
        """Join what a page renders against whether the page is access-controlled.

        A table permission says the data *may* be read; a page reference says
        something actually reads it; a page permission says who may load the
        page. Only the three together decide whether data reaches the public,
        and reviewing them separately is how sites leak in plain sight.
        """
        src = f"dataverse:{model.generation}"
        if self._index is None or not model.pages:
            return

        anon_roles = model.role_names(lambda r: r.is_anonymous)
        anon_readable = {p.table.lower() for p in model.permissions
                         if p.read and any(r in anon_roles for r in p.roles)}
        if not anon_readable:
            return

        for table in sorted(anon_readable):
            webapi = model.webapi_for(table)
            columns = webapi.field_list if webapi else []
            refs = self._references_for(table, columns or SENSITIVE_COLUMN_SEEDS)

            # One finding per page, not per occurrence: a template that reads a
            # table in four places is one thing to fix, not four.
            by_url: dict[str, list] = {}
            for ref in refs:
                if ref.page_id and ref.url and not model.protecting_rules(ref.page_id):
                    by_url.setdefault(ref.url, []).append(ref)

            for url, hits in sorted(by_url.items()):
                ref = hits[0]
                page = model.page_by_id(ref.page_id)
                sensitive = sorted({c for h in hits for c in h.columns
                                    if is_sensitive_column(c)})
                risky = sensitive or is_sensitive_table(table)
                if not risky and is_portal_content(table):
                    continue  # CMS content on a public page is the site working

                webapi_open = bool(webapi and webapi.enabled)
                steerable = any(h.visitor_input for h in hits)
                constraints = sorted({c for h in hits for c in h.constraints})
                constrained = all(h.constrained for h in hits) and bool(constraints)

                severity, verdict = _page_exposure_severity(
                    webapi_open, steerable, constrained, bool(sensitive), risky)

                how = "; ".join(sorted({f"{h.how} (line {h.line})" for h in hits})[:4])
                detail = (
                    f"'{url}' renders '{table}' via {how}, and no web page access "
                    "control rule covers it (its own or any ancestor's).")
                if webapi_open:
                    detail += (" The Web API is also enabled for this table, so a "
                               "visitor can query it directly rather than only seeing "
                               "what the page chooses to emit.")
                elif steerable:
                    detail += (" The query reads visitor-supplied input "
                               "(request parameters), so the visitor — not the page — "
                               "influences which rows come back.")
                elif constrained:
                    detail += (" The Web API is off for this table, so this is a "
                               "server-side render: the page emits only what its query "
                               f"selects, and that query is constrained ({', '.join(constraints)}).")
                else:
                    detail += (" The Web API is off for this table, so this is a "
                               "server-side render and the visitor cannot compose their "
                               "own query. No filter or condition was detected in the "
                               "query block, so it may return the whole table.")
                if sensitive:
                    detail += (" Columns matching personal-data patterns appear in the "
                               f"same query block: {', '.join(sensitive)}.")
                detail += f" {verdict}"

                report.add(Finding(
                    severity, "Unprotected page renders anonymously-readable data",
                    table=table, detail=detail, source=src,
                    evidence={
                        "url": url,
                        "page": page.name if page else ref.source_name,
                        "channel": ("Web API + page" if webapi_open else
                                    "page render (server-side)"),
                        "query_constraints": ", ".join(constraints) or "(none detected)",
                        "visitor_controlled_input": steerable,
                        "occurrences": len(hits),
                        "page_record": model.record_url("webpage", ref.page_id),
                        "content_record": ref.config_url,
                        "how": how,
                        "sensitive_columns": ", ".join(sensitive) or "(none detected)",
                        "page_permission": "none (inherited rules checked)",
                        "query": ref.block or ref.snippet,
                    }))

    def _analyse_forms(self, report: Report, model: SchemaModel) -> None:
        """Entity and web forms are the write channel; unprotected ones accept input."""
        src = f"dataverse:{model.generation}"
        if not model.entity_forms:
            return

        pages_by_form: dict[str, list] = {}
        for page in model.pages:
            for ref_id in (page.entity_form_id, page.web_form_id):
                if ref_id:
                    pages_by_form.setdefault(ref_id.lower(), []).append(page)

        for form in model.entity_forms:
            hosted = pages_by_form.get(form.id.lower(), [])
            open_pages = [p for p in hosted if not model.protecting_rules(p.id)]
            mode = (form.mode or "unknown").lower()
            writes = mode in ("insert", "edit") or mode == "unknown"
            if not (writes and open_pages):
                continue
            urls = [f"{self.portal_url.rstrip('/')}{p.path}" if self.portal_url else p.path
                    for p in open_pages]
            severity = (Severity.HIGH if is_sensitive_table(form.table)
                        else Severity.MEDIUM)
            report.add(Finding(
                severity, "Form on an unprotected page writes to a table",
                table=form.table,
                detail=(f"Entity form '{form.name}' is in {form.mode or 'an unknown'} "
                        f"mode against '{form.table}' and sits on "
                        f"{len(open_pages)} page(s) with no web page access control "
                        "rule. Unauthenticated visitors can reach the form; whether "
                        "they can submit depends on the table permission behind it, so "
                        "confirm the two agree. Forms are the write channel a "
                        "permission-only review misses."),
                source=src,
                evidence={"form": form.name, "mode": form.mode or "(unset)",
                          "pages": ", ".join(urls[:5]) or "(not placed on a page)",
                          "form_record": model.record_url("entityform", form.id)}))

    def _analyse_files(self, report: Report, model: SchemaModel) -> None:
        """Published files sit outside the table-permission model.

        A web file is served from its own URL and is governed by the page
        permissions of its parent page, not by any table permission. A file
        whose parent page is unprotected is public, however locked down the
        Dataverse side is.
        """
        src = f"dataverse:{model.generation}"
        if not model.files:
            return

        open_files = [f for f in model.files
                      if not f.parent_page_id or not model.protecting_rules(f.parent_page_id)]
        if not open_files:
            return
        report.add(Finding(
            Severity.LOW, "Published files are publicly reachable",
            detail=(f"{len(open_files)} of {len(model.files)} web file(s) hang off a "
                    "page with no Restrict Read rule, so they are downloadable without "
                    "signing in. Web files are served from their own URL and are not "
                    "governed by table permissions, so a locked-down permission model "
                    "does not protect them. Confirm none carries internal or personal "
                    "data."),
            source=src,
            evidence={"unprotected": len(open_files), "total": len(model.files),
                      "examples": ", ".join(f.name for f in open_files[:5])}))

    def _analyse_solutions(self, report: Report) -> None:
        """Report installed Power Pages solutions against Microsoft's published release.

        The reference point is fetched from Microsoft rather than hardcoded: any
        constant baked in here would be wrong within a month.
        """
        try:
            rows = self.client.portal_solutions()
        except DataverseError:
            return
        if not rows:
            return

        solutions = []
        for row in rows:
            version = str(row.get("version") or "")
            released = _release_date(version)
            solutions.append({
                "name": str(row.get("uniquename") or ""),
                "friendly": str(row.get("friendlyname") or ""),
                "version": version,
                "released": released.isoformat() if released else "",
                "months_old": _months_since(released) if released else None,
            })
        solutions.sort(key=lambda s: s["name"].lower())
        report.context["portal_solutions"] = solutions

        base = next((s for s in solutions if s["name"] == "CDSBasePortal"), None)
        if base:
            report.context["portal_version"] = base["version"]
            report.context["portal_version_source"] = "CDSBasePortal solution"

        current = versions.fetch_current_release() if self.check_versions else None
        if current:
            report.context["published_release"] = {
                "version": current.version,
                "released": current.released.isoformat(),
                "source": current.source,
            }

        dated = [s for s in solutions if s["months_old"] is not None]
        if not dated:
            return

        # Two independent yardsticks, so the finding stands up without network
        # access and gets sharper with it.
        newest_here = min(s["months_old"] for s in dated)
        reference = (_months_since(current.released) if current else None)
        cutoff = max(newest_here + 12, 12)
        behind = sorted((s for s in dated if s["months_old"] >= cutoff),
                        key=lambda s: -s["months_old"])
        if not behind:
            return

        worst = behind[0]
        detail = (
            f"{len(behind)} installed Power Pages solution(s) are well behind the rest "
            f"of this environment. The oldest is {worst['name']} {worst['version']} "
            f"(~{worst['months_old']} months old), while the newest portal solution "
            f"here is only ~{newest_here} months old — so this environment has already "
            "received more recent portal releases that these packages missed.")
        if current:
            detail += (f" Microsoft's published current release is {current.label}, "
                       f"from {current.source}.")
        detail += (" The website host updates itself, but Dataverse solutions do not, "
                   "and Microsoft does not certify an unsupported solution version to "
                   "run against a current host — so fixes shipped in between are "
                   "absent.")

        evidence = {s["name"]: f"{s['version']} (~{s['months_old']} months)"
                    for s in behind[:8]}
        evidence["newest_portal_solution_here"] = f"~{newest_here} months old"
        if current:
            evidence["published_current_release"] = current.label
            evidence["reference"] = current.source
        report.add(Finding(
            Severity.MEDIUM if worst["months_old"] >= (reference or 36) else Severity.LOW,
            "Power Pages solutions are behind the rest of the environment",
            detail=detail, source="dataverse", evidence=evidence))


    def _analyse_settings(self, report: Report, model: SchemaModel) -> None:
        src = f"dataverse:{model.generation}"
        for setting in model.settings:
            entry = NOTABLE_SETTINGS.get(setting.name.lower())
            if not entry:
                continue
            risky_values, why = entry
            if setting.value.strip().lower() not in risky_values:
                continue
            report.add(Finding(
                Severity.MEDIUM, "Site setting weakens the security posture",
                detail=f"{setting.name} = {setting.value}. {why}",
                source=src,
                evidence={"setting": setting.name, "value": setting.value,
                          "website": model.website_name(setting.website_id)}))

    # --- correlation ---------------------------------------------------------

    def _correlate(self, report: Report) -> None:
        """Tie externally-observed leaks to the configuration that causes them."""
        exposed = set(report.context.get("anon_exposed_tables", []))
        if not exposed:
            return
        index: dict[str, list[tuple[SchemaModel, TablePermission]]] = {}
        for model in self.models:
            for perm in model.permissions:
                index.setdefault(perm.table.lower(), []).append((model, perm))

        for table in sorted(exposed):
            logical = table[:-1] if table.endswith("s") else table
            matches = index.get(logical.lower()) or index.get(table.lower()) or []
            if not matches:
                report.add(Finding(
                    Severity.HIGH, "External leak with no matching table permission",
                    table=table,
                    detail=("The anonymous scanner read this table from the internet, but "
                            "no table permission on the expected entity was found in the "
                            "configuration. Investigate: it may be exposed under a "
                            "different entity name, through an entity list OData feed, or "
                            "by a Liquid template that bypasses the permission model."),
                    source="correlation"))
                continue
            causes = "; ".join(
                f"[{m.label}] {p.name} (read={p.read}, scope={p.scope or 'unset'}, "
                f"roles={', '.join(p.roles) or 'none'})" for m, p in matches)
            anon_named = sorted({
                r for m, p in matches for r in p.roles
                if r in m.role_names(lambda x: x.is_anonymous)})
            report.add(Finding(
                Severity.CRITICAL if anon_named else Severity.HIGH,
                "External leak tied to configured permissions",
                table=table,
                detail=(f"The anonymous scanner read '{table}' from the internet and the "
                        f"Dataverse configuration explains it:\n{causes}"
                        + (f"\nAnonymous role(s) involved: {', '.join(anon_named)}."
                           if anon_named else
                           "\nNo anonymous role is bound to these permissions, so the read "
                           "came through another channel — review entity lists and Liquid "
                           "templates for this table.")),
                source="correlation",
                evidence={"root_cause_permissions": len(matches),
                          "anonymous_roles": ", ".join(anon_named) or "(none)"}))


# --- helpers -----------------------------------------------------------------


def _resolve_columns(perm: TablePermission, webapi, profiles) -> tuple[str, list[str]]:
    """Describe which columns a permission actually reaches, and flag likely PII.

    Precedence per the Power Pages model: the table permission gates the table,
    ``Webapi/<entity>/fields`` decides which columns the Web API publishes, and
    column permission profiles narrow that further when bound to the role (and
    when the site is not on the enhanced authorization model).
    """
    if not perm.read:
        return "(no read privilege)", []
    if webapi is None:
        return "(no Web API site setting; exposure depends on another channel)", []
    if not webapi.enabled:
        return "(Web API disabled for this table)", []

    published = [] if webapi.all_fields else webapi.field_list

    profile_reads: set[str] = set()
    profile_all_read = False
    for profile in profiles:
        if "Read" in profile.all_permissions:
            profile_all_read = True
        profile_reads.update(c.column for c in profile.columns if "Read" in c.permissions)

    if profiles and not profile_all_read:
        if not profile_reads:
            return "(column profile grants no Read on any column)", []
        columns = sorted(set(published) & profile_reads) if published else sorted(profile_reads)
        if not columns:
            return "(Webapi fields and column profile do not overlap)", []
        return ", ".join(columns), sorted(c for c in columns if is_sensitive_column(c))

    if not published:
        return "ALL columns (Webapi fields = *)", []
    return ", ".join(published), sorted(c for c in published if is_sensitive_column(c))


def _setting_is(model: SchemaModel, name: str, expected: str) -> bool:
    target = name.lower()
    for setting in model.settings:
        if setting.name.lower() == target:
            return setting.value.strip().lower() == expected
    return False


def _filter_to_website(model: SchemaModel, needle: str) -> SchemaModel:
    """Keep only records belonging to the named website (plus unscoped ones)."""
    ids = {w.id.lower() for w in model.websites if needle in w.name.lower()}
    if not ids:
        return model

    def keep(website_id: str) -> bool:
        return not website_id or website_id.lower() in ids

    model.websites = [w for w in model.websites if w.id.lower() in ids]
    model.roles = [r for r in model.roles if keep(r.website_id)]
    model.permissions = [p for p in model.permissions if keep(p.website_id)]
    model.profiles = [p for p in model.profiles if keep(p.website_id)]
    model.settings = [s for s in model.settings if keep(s.website_id)]
    model.webapi = [w for w in model.webapi if keep(w.website_id)]
    model.entity_lists = [e for e in model.entity_lists if keep(e.website_id)]
    model.entity_forms = [e for e in model.entity_forms if keep(e.website_id)]
    model.page_rules = [r for r in model.page_rules if keep(r.website_id)]
    return model
