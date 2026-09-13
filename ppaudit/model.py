"""Typed model of a Power Pages site's Dataverse security configuration.

This module does the *reading*. It pulls every configuration table that
governs who can reach which data through a Power Pages site, for each
configuration generation present in the environment:

* websites, web roles (and which role is the Anonymous / Authenticated role)
* table permissions — scope, privileges, role bindings, parent chain
* column permission profiles and their per-column grants
* site settings — the ``Webapi/<entity>/enabled`` + ``/fields`` pair and the
  authentication / header / tracing settings that change the attack surface
* entity lists (the OData feed channel) and entity forms (create/edit channel)
* web page access control rules — which roles gate which pages

Rows are fetched whole (these tables are tiny) and each logical field is
resolved against an ordered candidate list, so the same code reads the
``adx_`` standard data model and the ``mspp_`` enhanced data model without
emitting a ``$select`` that would 400 on the other generation.

Analysis and severity live in :mod:`ppaudit.audit`; this module only reports
what is configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import (
    COLUMN_PERMISSION_LABELS,
    FIELD_CANDIDATES,
    FORMATTED_VALUE,
    PAGE_RULE_RIGHT_LABELS,
    SCOPE_FALLBACK_LABELS,
    SECURITY_SETTING_PREFIXES,
    WEBAPI_ENABLED_PREFIX,
    WEBAPI_ENABLED_SUFFIX,
    WEBAPI_FIELDS_SUFFIX,
)
from .dataverse import DataverseClient
from .references import ContentSource

ANONYMOUS = "anonymous"
AUTHENTICATED = "authenticated"


# --- field resolution --------------------------------------------------------


class FieldResolver:
    """Resolves logical field names to whatever the row actually carries."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix

    def candidates(self, logical: str) -> list[str]:
        return [c.format(p=self.prefix) for c in FIELD_CANDIDATES.get(logical, [])]

    def raw(self, row: dict[str, Any], logical: str, default: Any = None) -> Any:
        for name in self.candidates(logical):
            if row.get(name) is not None:
                return row[name]
        return default

    def resolved(self, row: dict[str, Any], logical: str) -> str:
        """Which candidate field this row actually carries, for writing back."""
        for name in self.candidates(logical):
            if row.get(name) is not None:
                return name
        return ""

    def text(self, row: dict[str, Any], logical: str, default: str = "") -> str:
        value = self.raw(row, logical)
        return default if value is None else str(value)

    def flag(self, row: dict[str, Any], logical: str) -> bool:
        return bool(self.raw(row, logical, False))

    def label(self, row: dict[str, Any], logical: str,
              fallback: dict[int, str] | None = None) -> str:
        """Prefer the server-supplied option-set label; fall back to the map."""
        for name in self.candidates(logical):
            formatted = row.get(name + FORMATTED_VALUE)
            if formatted:
                return str(formatted)
        value = self.raw(row, logical)
        if value is None:
            return ""
        if fallback:
            try:
                return fallback.get(int(value), str(value))
            except (TypeError, ValueError):
                pass
        return str(value)

    def multi_labels(self, row: dict[str, Any], logical: str,
                     fallback: dict[int, str]) -> list[str]:
        """Read a multi-select picklist as a list of labels."""
        for name in self.candidates(logical):
            formatted = row.get(name + FORMATTED_VALUE)
            if formatted:
                return [p.strip() for p in str(formatted).split(";") if p.strip()]
        value = self.raw(row, logical)
        if value in (None, ""):
            return []
        out = []
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                out.append(fallback.get(int(part), part))
            except ValueError:
                out.append(part)
        return out


# --- model -------------------------------------------------------------------


@dataclass
class WebRole:
    id: str
    name: str
    is_anonymous: bool = False
    is_authenticated: bool = False
    website_id: str = ""
    description: str = ""

    @property
    def kind(self) -> str:
        if self.is_anonymous and self.is_authenticated:
            return "Anonymous AND Authenticated Users role"
        if self.is_anonymous:
            return "Anonymous Users role"
        if self.is_authenticated:
            return "Authenticated Users role"
        return "Named role"


@dataclass
class TablePermission:
    id: str
    name: str
    table: str
    scope: str
    read: bool = False
    write: bool = False
    create: bool = False
    delete: bool = False
    append: bool = False
    appendto: bool = False
    roles: list[str] = field(default_factory=list)
    website_id: str = ""
    parent_id: str = ""
    contact_relationship: str = ""
    account_relationship: str = ""
    parent_relationship: str = ""

    def privileges(self) -> list[str]:
        flags = [("Read", self.read), ("Write", self.write), ("Create", self.create),
                 ("Delete", self.delete), ("Append", self.append),
                 ("AppendTo", self.appendto)]
        return [n for n, on in flags if on]

    @property
    def mutating(self) -> list[str]:
        flags = [("Write", self.write), ("Create", self.create), ("Delete", self.delete)]
        return [n for n, on in flags if on]


@dataclass
class ColumnPermission:
    id: str
    column: str
    permissions: list[str] = field(default_factory=list)
    profile_id: str = ""


@dataclass
class ColumnPermissionProfile:
    id: str
    name: str
    table: str
    all_permissions: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    website_id: str = ""
    columns: list[ColumnPermission] = field(default_factory=list)


@dataclass
class WebApiTable:
    """The ``Webapi/<entity>/enabled`` + ``/fields`` site-setting pair."""

    entity: str
    enabled: bool = False
    enabled_raw: str = ""
    fields_raw: str = ""
    website_id: str = ""
    enabled_setting_id: str = ""
    fields_setting_id: str = ""

    @property
    def all_fields(self) -> bool:
        return self.fields_raw.strip() in ("*", "")

    @property
    def field_list(self) -> list[str]:
        if self.all_fields:
            return []
        return [f.strip() for f in self.fields_raw.split(",") if f.strip()]


@dataclass
class SiteSetting:
    id: str
    name: str
    value: str
    website_id: str = ""


@dataclass
class EntityList:
    id: str
    name: str
    table: str
    odata_enabled: bool = False
    odata_entityset: str = ""
    odata_fields: str = ""
    website_id: str = ""
    view_fetchxml: str = ""
    filter_fetchxml: str = ""
    settings: str = ""


@dataclass
class EntityForm:
    id: str
    name: str
    table: str
    mode: str = ""
    website_id: str = ""


@dataclass
class PageAccessRule:
    id: str
    name: str
    right: str
    scope: str
    page_id: str = ""
    page_name: str = ""
    roles: list[str] = field(default_factory=list)
    website_id: str = ""


@dataclass
class WebPage:
    """A page of the site, with the content it renders and its resolved URL."""

    id: str
    name: str
    partial_url: str = ""
    parent_id: str = ""
    title: str = ""
    copy: str = ""
    custom_js: str = ""
    page_template_id: str = ""
    entity_list_id: str = ""
    entity_form_id: str = ""
    web_form_id: str = ""
    website_id: str = ""
    path: str = ""          # resolved from the parent chain


@dataclass
class WebTemplate:
    """Liquid source, rendered by whichever pages use it via a page template."""

    id: str
    name: str
    source: str = ""
    website_id: str = ""


@dataclass
class PageTemplate:
    id: str
    name: str
    web_template_id: str = ""
    website_id: str = ""


@dataclass
class ContentSnippet:
    id: str
    name: str
    value: str = ""
    website_id: str = ""


@dataclass
class Website:
    id: str
    name: str


@dataclass
class SchemaModel:
    """Everything read for one configuration generation."""

    generation: str                     # "adx" | "mspp"
    label: str                          # "Standard data model" | "Enhanced data model"
    description: str = ""
    org_url: str = ""                   # for building maker deep links
    entity_sets: dict[str, str] = field(default_factory=dict)
    perm_name_field: str = ""           # the column holding a permission's label
    websites: list[Website] = field(default_factory=list)
    roles: list[WebRole] = field(default_factory=list)
    permissions: list[TablePermission] = field(default_factory=list)
    profiles: list[ColumnPermissionProfile] = field(default_factory=list)
    webapi: list[WebApiTable] = field(default_factory=list)
    settings: list[SiteSetting] = field(default_factory=list)
    entity_lists: list[EntityList] = field(default_factory=list)
    entity_forms: list[EntityForm] = field(default_factory=list)
    page_rules: list[PageAccessRule] = field(default_factory=list)
    pages: list[WebPage] = field(default_factory=list)
    templates: list[WebTemplate] = field(default_factory=list)
    page_templates: list[PageTemplate] = field(default_factory=list)
    snippets: list[ContentSnippet] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    # --- convenience views ---------------------------------------------------

    @property
    def in_use(self) -> bool:
        """True when this generation actually holds configuration.

        Both generations answer queries in most environments; only the one the
        site was built on has content. An empty one must not be analysed, or it
        contradicts the real model with 'nothing is configured' findings.
        """
        return bool(self.websites or self.roles or self.permissions
                    or self.webapi or self.entity_lists)

    def website_name(self, website_id: str) -> str:
        for site in self.websites:
            if site.id.lower() == (website_id or "").lower():
                return site.name
        return website_id or "(unscoped)"

    def anonymous_roles(self) -> list[WebRole]:
        return [r for r in self.roles if r.is_anonymous]

    def authenticated_roles(self) -> list[WebRole]:
        return [r for r in self.roles if r.is_authenticated]

    def role_names(self, predicate) -> set[str]:
        return {r.name for r in self.roles if predicate(r)}

    def webapi_for(self, table: str) -> WebApiTable | None:
        table = (table or "").lower()
        for entry in self.webapi:
            if entry.entity.lower() == table:
                return entry
        return None

    def profiles_for(self, table: str) -> list[ColumnPermissionProfile]:
        table = (table or "").lower()
        return [p for p in self.profiles if p.table.lower() == table]

    def permissions_for_role(self, role_name: str) -> list[TablePermission]:
        return [p for p in self.permissions if role_name in p.roles]

    def record_url(self, key: str, record_id: str) -> str:
        """Deep link to a configuration record in the model-driven maker UI.

        ``main.aspx`` without an ``appid`` resolves to whichever app the signed-in
        user has, which is what a reviewer opening the link actually wants.
        """
        entity_set = self.entity_sets.get(key)
        if not (self.org_url and entity_set and record_id):
            return ""
        logical = entity_set[:-1] if entity_set.endswith("s") else entity_set
        return (f"{self.org_url}/main.aspx?pagetype=entityrecord"
                f"&etn={logical}&id={record_id}")

    def content_sources(self, base_url: str = "") -> list[ContentSource]:
        """Every piece of content that can render data, with a URL where one exists.

        A web template has no URL of its own, so it inherits the URLs of the
        pages that render it through a page template — that is the chain a
        reviewer has to walk by hand otherwise.
        """
        base = (base_url or "").rstrip("/")
        sources: list[ContentSource] = []

        def page_url(page: WebPage) -> str:
            return f"{base}{page.path}" if base and page.path else page.path

        pages_by_template: dict[str, list[WebPage]] = {}
        for page in self.pages:
            if page.page_template_id:
                pages_by_template.setdefault(page.page_template_id.lower(), []).append(page)

        for page in self.pages:
            if page.copy:
                sources.append(ContentSource(
                    kind="Web page copy", name=page.name, text=page.copy,
                    url=page_url(page), page_names=[page.name]))
            if page.custom_js:
                sources.append(ContentSource(
                    kind="Web page JavaScript", name=page.name, text=page.custom_js,
                    url=page_url(page), page_names=[page.name]))

        template_pages: dict[str, list[WebPage]] = {}
        for page_template in self.page_templates:
            if not page_template.web_template_id:
                continue
            hosted = pages_by_template.get(page_template.id.lower(), [])
            template_pages.setdefault(
                page_template.web_template_id.lower(), []).extend(hosted)

        for template in self.templates:
            if not template.source:
                continue
            hosted = template_pages.get(template.id.lower(), [])
            urls = [page_url(p) for p in hosted if page_url(p)]
            sources.append(ContentSource(
                kind="Web template (Liquid)", name=template.name, text=template.source,
                url=urls[0] if urls else "",
                page_names=[p.name for p in hosted],
                note=("rendered by " + ", ".join(urls[:5]) + ("…" if len(urls) > 5 else ""))
                if urls else
                "not bound to a page template — may be pulled in by {% include %}"))

        for snippet in self.snippets:
            if snippet.value:
                sources.append(ContentSource(
                    kind="Content snippet", name=snippet.name, text=snippet.value,
                    note="rendered wherever {% editable snippets['...'] %} names it"))

        list_pages: dict[str, list[WebPage]] = {}
        for page in self.pages:
            if page.entity_list_id:
                list_pages.setdefault(page.entity_list_id.lower(), []).append(page)
        for entity_list in self.entity_lists:
            text = "\n".join(t for t in (entity_list.view_fetchxml,
                                         entity_list.filter_fetchxml,
                                         entity_list.settings) if t)
            if not text:
                continue
            hosted = list_pages.get(entity_list.id.lower(), [])
            urls = [page_url(p) for p in hosted if page_url(p)]
            sources.append(ContentSource(
                kind="Entity list (view/filter FetchXML)", name=entity_list.name,
                text=text, url=urls[0] if urls else "",
                page_names=[p.name for p in hosted],
                note=("shown on " + ", ".join(urls[:5])) if urls else
                     "not placed on a page in this configuration"))
        return sources

    def resolve_page_paths(self) -> None:
        """Walk the parent chain to turn partial URLs into full site paths."""
        by_id = {p.id.lower(): p for p in self.pages if p.id}
        for page in self.pages:
            parts: list[str] = []
            current: WebPage | None = page
            seen: set[str] = set()
            while current and current.id.lower() not in seen:
                seen.add(current.id.lower())
                partial = (current.partial_url or "").strip("/")
                if partial and partial != "/":
                    parts.append(partial)
                current = by_id.get((current.parent_id or "").lower())
            page.path = "/" + "/".join(reversed(parts)) if parts else "/"

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly projection used by the JSON report."""
        return {
            "generation": self.generation,
            "label": self.label,
            "websites": [{"id": w.id, "name": w.name} for w in self.websites],
            "web_roles": [
                {"name": r.name, "kind": r.kind, "anonymous": r.is_anonymous,
                 "authenticated": r.is_authenticated,
                 "website": self.website_name(r.website_id)}
                for r in self.roles],
            "table_permissions": [
                {"name": p.name, "table": p.table, "scope": p.scope,
                 "privileges": p.privileges(), "roles": p.roles,
                 "website": self.website_name(p.website_id),
                 "parent_permission": bool(p.parent_id)}
                for p in self.permissions],
            "column_permission_profiles": [
                {"name": p.name, "table": p.table, "roles": p.roles,
                 "all_column_permissions": p.all_permissions,
                 "columns": [{"column": c.column, "permissions": c.permissions}
                             for c in p.columns]}
                for p in self.profiles],
            "webapi": [
                {"entity": w.entity, "enabled": w.enabled, "fields": w.fields_raw or "*"}
                for w in self.webapi],
            "entity_lists": [
                {"name": e.name, "table": e.table, "odata_enabled": e.odata_enabled,
                 "odata_entityset": e.odata_entityset, "odata_fields": e.odata_fields}
                for e in self.entity_lists],
            "page_access_rules": [
                {"name": r.name, "right": r.right, "scope": r.scope,
                 "page": r.page_name, "roles": r.roles}
                for r in self.page_rules],
            "security_settings": [
                {"name": s.name, "value": s.value} for s in self.security_settings()],
            "errors": self.errors,
        }

    def security_settings(self) -> list[SiteSetting]:
        return [s for s in self.settings
                if any(s.name.lower().startswith(p.lower())
                       for p in SECURITY_SETTING_PREFIXES)]


# --- loader ------------------------------------------------------------------


class ConfigLoader:
    """Reads one configuration generation into a :class:`SchemaModel`."""

    def __init__(self, client: DataverseClient, generation: str, cfg: dict[str, Any]) -> None:
        self.client = client
        self.gen = generation
        self.cfg = cfg
        self.sets = cfg["sets"]
        self.nav = cfg["nav"]
        self.r = FieldResolver(cfg["prefix"])

    def load(self) -> SchemaModel:
        model = SchemaModel(generation=self.gen, label=self.cfg["label"],
                            description=self.cfg.get("description", ""),
                            org_url=self.client.org_url,
                            entity_sets=dict(self.sets))
        self._load_websites(model)
        self._load_roles(model)
        self._load_permissions(model)
        self._load_column_permissions(model)
        self._load_settings(model)
        self._load_entity_lists(model)
        self._load_entity_forms(model)
        self._load_content(model)
        model.resolve_page_paths()
        self._load_page_rules(model)
        return model

    def _fetch(self, model: SchemaModel, key: str, query: str = "") -> list[dict[str, Any]]:
        entity_set = self.sets.get(key)
        if not entity_set:
            return []
        rows, err = self.client.try_get(entity_set, query)
        if err:
            model.errors[entity_set] = err
        return rows

    # -- individual tables ----------------------------------------------------

    def _load_websites(self, model: SchemaModel) -> None:
        for row in self._fetch(model, "website"):
            model.websites.append(Website(
                id=self.r.text(row, "website_id"),
                name=self.r.text(row, "website_name", "(unnamed site)")))

    def _load_roles(self, model: SchemaModel) -> None:
        for row in self._fetch(model, "webrole"):
            model.roles.append(WebRole(
                id=self.r.text(row, "role_id"),
                name=self.r.text(row, "role_name", "(unnamed role)"),
                is_anonymous=self.r.flag(row, "role_anonymous"),
                is_authenticated=self.r.flag(row, "role_authenticated"),
                website_id=self.r.text(row, "website_ref"),
                description=self.r.text(row, "role_description")))

    def _load_permissions(self, model: SchemaModel) -> None:
        nav = self.nav["entitypermission_webrole"]
        rows = self._fetch(model, "entitypermission", f"$expand={nav}")
        role_field = self.r.candidates("role_name")[0]
        for row in rows:
            if not model.perm_name_field:
                model.perm_name_field = self.r.resolved(row, "perm_name")
            bound = [str(r.get(role_field) or "(unnamed role)") for r in row.get(nav, [])]
            model.permissions.append(TablePermission(
                id=self.r.text(row, "perm_id"),
                name=self.r.text(row, "perm_name", "(unnamed permission)"),
                table=self.r.text(row, "perm_entity", "(unknown table)"),
                scope=self.r.label(row, "perm_scope", SCOPE_FALLBACK_LABELS),
                read=self.r.flag(row, "perm_read"),
                write=self.r.flag(row, "perm_write"),
                create=self.r.flag(row, "perm_create"),
                delete=self.r.flag(row, "perm_delete"),
                append=self.r.flag(row, "perm_append"),
                appendto=self.r.flag(row, "perm_appendto"),
                roles=bound,
                website_id=self.r.text(row, "website_ref"),
                parent_id=self.r.text(row, "perm_parent"),
                contact_relationship=self.r.text(row, "perm_contact_rel"),
                account_relationship=self.r.text(row, "perm_account_rel"),
                parent_relationship=self.r.text(row, "perm_parent_rel")))

    def _load_column_permissions(self, model: SchemaModel) -> None:
        nav = self.nav["columnpermissionprofile_webrole"]
        role_field = self.r.candidates("role_name")[0]
        profiles: dict[str, ColumnPermissionProfile] = {}
        for row in self._fetch(model, "columnpermissionprofile", f"$expand={nav}"):
            profile = ColumnPermissionProfile(
                id=self.r.text(row, "cpp_id"),
                name=self.r.text(row, "cpp_name", "(unnamed profile)"),
                table=self.r.text(row, "cpp_table", "(unknown table)"),
                all_permissions=self.r.multi_labels(row, "cpp_all", COLUMN_PERMISSION_LABELS),
                roles=[str(r.get(role_field) or "(unnamed role)") for r in row.get(nav, [])],
                website_id=self.r.text(row, "website_ref"))
            profiles[profile.id.lower()] = profile
            model.profiles.append(profile)

        for row in self._fetch(model, "columnpermission"):
            permission = ColumnPermission(
                id=self.r.text(row, "cp_id"),
                column=self.r.text(row, "cp_column", "(unknown column)"),
                permissions=self.r.multi_labels(row, "cp_permissions", COLUMN_PERMISSION_LABELS),
                profile_id=self.r.text(row, "cp_profile_ref"))
            owner = profiles.get(permission.profile_id.lower())
            if owner:
                owner.columns.append(permission)

    def _load_settings(self, model: SchemaModel) -> None:
        webapi: dict[str, WebApiTable] = {}
        for row in self._fetch(model, "sitesetting"):
            name = self.r.text(row, "setting_name")
            if not name:
                continue
            value = self.r.text(row, "setting_value")
            website_id = self.r.text(row, "website_ref")
            model.settings.append(SiteSetting(
                id=self.r.text(row, "setting_id"), name=name,
                value=value, website_id=website_id))

            if not name.lower().startswith(WEBAPI_ENABLED_PREFIX.lower()):
                continue
            rest = name[len(WEBAPI_ENABLED_PREFIX):]
            lowered = rest.lower()
            setting_id = self.r.text(row, "setting_id")
            if lowered.endswith(WEBAPI_ENABLED_SUFFIX):
                entity = rest[: -len(WEBAPI_ENABLED_SUFFIX)]
                entry = webapi.setdefault(entity.lower(), WebApiTable(entity=entity))
                entry.entity = entity
                entry.enabled_raw = value
                entry.enabled = value.strip().lower() == "true"
                entry.website_id = website_id
                entry.enabled_setting_id = setting_id
            elif lowered.endswith(WEBAPI_FIELDS_SUFFIX):
                entity = rest[: -len(WEBAPI_FIELDS_SUFFIX)]
                entry = webapi.setdefault(entity.lower(), WebApiTable(entity=entity))
                entry.entity = entity
                entry.fields_raw = value
                entry.website_id = entry.website_id or website_id
                entry.fields_setting_id = setting_id
        model.webapi = sorted(webapi.values(), key=lambda w: w.entity.lower())

    def _load_entity_lists(self, model: SchemaModel) -> None:
        for row in self._fetch(model, "entitylist"):
            model.entity_lists.append(EntityList(
                id=self.r.text(row, "list_id"),
                name=self.r.text(row, "list_name", "(unnamed list)"),
                table=self.r.text(row, "list_entity", "(unknown table)"),
                odata_enabled=self.r.flag(row, "list_odata_enabled"),
                odata_entityset=self.r.text(row, "list_odata_entityset"),
                odata_fields=self.r.text(row, "list_odata_fields"),
                website_id=self.r.text(row, "website_ref"),
                view_fetchxml=self.r.text(row, "list_view"),
                filter_fetchxml=self.r.text(row, "list_filter"),
                settings=self.r.text(row, "list_settings")))

    def _load_entity_forms(self, model: SchemaModel) -> None:
        for row in self._fetch(model, "entityform"):
            model.entity_forms.append(EntityForm(
                id=self.r.text(row, "form_id"),
                name=self.r.text(row, "form_name", "(unnamed form)"),
                table=self.r.text(row, "form_entity", "(unknown table)"),
                mode=self.r.label(row, "form_mode"),
                website_id=self.r.text(row, "website_ref")))

    def _load_page_rules(self, model: SchemaModel) -> None:
        nav = self.nav["webpageaccessrule_webrole"]
        role_field = self.r.candidates("role_name")[0]
        pages = {p.id.lower(): p for p in model.pages}
        for row in self._fetch(model, "webpageaccessrule", f"$expand={nav}"):
            page_id = self.r.text(row, "rule_page_ref")
            page = pages.get(page_id.lower())
            model.page_rules.append(PageAccessRule(
                id=self.r.text(row, "rule_id"),
                name=self.r.text(row, "rule_name", "(unnamed rule)"),
                right=self.r.label(row, "rule_right", PAGE_RULE_RIGHT_LABELS),
                scope=self.r.label(row, "rule_scope"),
                page_id=page_id,
                page_name=f"{page.name} ({page.path})" if page else "(unknown page)",
                roles=[str(r.get(role_field) or "(unnamed role)") for r in row.get(nav, [])],
                website_id=self.r.text(row, "website_ref")))

    def _load_content(self, model: SchemaModel) -> None:
        """The renderable content: pages, Liquid templates and snippets."""
        for row in self._fetch(model, "webpage"):
            model.pages.append(WebPage(
                id=self.r.text(row, "page_id"),
                name=self.r.text(row, "page_name", "(unnamed page)"),
                partial_url=self.r.text(row, "page_partialurl"),
                parent_id=self.r.text(row, "page_parent"),
                title=self.r.text(row, "page_title"),
                copy=self.r.text(row, "page_copy"),
                custom_js=self.r.text(row, "page_customjs"),
                page_template_id=self.r.text(row, "page_pagetemplate_ref"),
                entity_list_id=self.r.text(row, "page_entitylist_ref"),
                entity_form_id=self.r.text(row, "page_entityform_ref"),
                web_form_id=self.r.text(row, "page_webform_ref"),
                website_id=self.r.text(row, "website_ref")))

        for row in self._fetch(model, "webtemplate"):
            model.templates.append(WebTemplate(
                id=self.r.text(row, "template_id"),
                name=self.r.text(row, "template_name", "(unnamed template)"),
                source=self.r.text(row, "template_source"),
                website_id=self.r.text(row, "website_ref")))

        for row in self._fetch(model, "pagetemplate"):
            model.page_templates.append(PageTemplate(
                id=self.r.text(row, "pagetemplate_id"),
                name=self.r.text(row, "pagetemplate_name", "(unnamed page template)"),
                web_template_id=self.r.text(row, "pagetemplate_template_ref"),
                website_id=self.r.text(row, "website_ref")))

        for row in self._fetch(model, "contentsnippet"):
            model.snippets.append(ContentSnippet(
                id=self.r.text(row, "snippet_id"),
                name=self.r.text(row, "snippet_name", "(unnamed snippet)"),
                value=self.r.text(row, "snippet_value"),
                website_id=self.r.text(row, "website_ref")))
