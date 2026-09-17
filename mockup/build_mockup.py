"""Build the sample reports from a fictional Power Pages site.

Everything here is invented: Contoso is a Microsoft fictional company, and the
``.example`` domain cannot resolve. No real environment is contacted. The
configuration is fed through the real audit, scanner-recording and probe code
paths — only the network calls are replaced — so the sample shows exactly what
the current renderers produce.

    python mockup/build_mockup.py          # writes mockup/sample_report.{html,md,json}
    python mockup/capture.py               # then screenshots into mockup/img/
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from ppaudit import audit as audit_module  # noqa: E402
from ppaudit import cli, pageprobe  # noqa: E402
from ppaudit.anonscan import AnonScanner, ProbeResult  # noqa: E402
from ppaudit.audit import DataverseAudit  # noqa: E402
from ppaudit.constants import CONFIG_SCHEMAS  # noqa: E402
from ppaudit.model import (  # noqa: E402
    ColumnPermission,
    ColumnPermissionProfile,
    ContentSnippet,
    EntityForm,
    EntityList,
    PageAccessRule,
    PageTemplate,
    PublishingState,
    SchemaModel,
    SiteSetting,
    TablePermission,
    WebApiTable,
    WebFile,
    WebPage,
    WebRole,
    WebTemplate,
    Website,
)
from ppaudit.report import Finding, Report, Severity  # noqa: E402

ORG = "https://contoso-demo.crm.dynamics.com"
PORTAL = "https://portal.contoso.example"
SITE = "3f1c9a52-0000-4000-8000-000000000001"


def _id(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


# --- the fictional site --------------------------------------------------------

EVENT_LOOKUP = """\
{% fetchxml registration %}
<fetch top="1">
  <entity name="cr7f3_eventregistration">
    <attribute name="cr7f3_fullname" />
    <attribute name="cr7f3_email" />
    <attribute name="cr7f3_mobilephone" />
    <filter>
      <condition attribute="cr7f3_reference" operator="eq" value="{{ request.params['ref'] }}" />
    </filter>
  </entity>
</fetch>
{% endfetchxml %}
{% for r in registration.results.entities %}
  <h2>Welcome back, {{ r.cr7f3_fullname }}</h2>
  <p>We will send updates to {{ r.cr7f3_email }}.</p>
{% endfor %}"""

PRODUCT_CATALOGUE = """\
{% fetchxml products %}
<fetch count="50">
  <entity name="product">
    <attribute name="name" />
    <attribute name="price" />
    <filter><condition attribute="statecode" operator="eq" value="0" /></filter>
  </entity>
</fetch>
{% endfetchxml %}"""

SPEAKERS = """\
<div class="speakers">
{% fetchxml speakers %}
<fetch>
  <entity name="contact">
    <attribute name="fullname" />
    <attribute name="emailaddress1" />
    <attribute name="telephone1" />
  </entity>
</fetch>
{% endfetchxml %}
</div>"""

STORE_LOCATOR_JS = """\
fetch('/_api/contacts?$select=fullname,emailaddress1,address1_city')
  .then(r => r.json())
  .then(d => renderStores(d.value));"""


def build_model() -> SchemaModel:
    cfg = CONFIG_SCHEMAS["adx"]
    model = SchemaModel(
        generation="adx", label=cfg["label"], description=cfg["description"],
        org_url=ORG, entity_sets=dict(cfg["sets"]),
        perm_name_field="adx_entityname", cpp_name_field="adx_profilename",
        websites=[Website(id=SITE, name="Contoso Community Portal",
                          primary_domain="portal.contoso.example")])

    def role(n, name, anon=False, auth=False):
        return WebRole(id=_id(n), name=name, is_anonymous=anon,
                       is_authenticated=auth, website_id=SITE)

    model.roles = [
        role(1, "Anonymous Users", anon=True),
        role(2, "Authenticated Users", auth=True),
        role(3, "Case Managers"),
        role(4, "Legacy Public Access", anon=True, auth=True),
    ]

    def perm(n, name, table, scope, roles, **flags):
        return TablePermission(id=_id(100 + n), name=name, table=table, scope=scope,
                               roles=list(roles), website_id=SITE, **flags)

    model.permissions = [
        perm(1, "Store locator", "contact", "Global", ["Anonymous Users"], read=True),
        perm(2, "Products", "product", "Global", ["Anonymous Users"], read=True),
        perm(3, "Blogs Global", "adx_blogpost", "Global", ["Anonymous Users"], read=True),
        perm(4, "Event registrations", "cr7f3_eventregistration", "Global",
             ["Anonymous Users"], read=True),
        perm(5, "Lead capture", "lead", "Global", ["Anonymous Users"], create=True),
        perm(6, "My cases", "incident", "Contact", ["Authenticated Users"],
             read=True, write=True, create=True, append=True,
             contact_relationship="incident_customer_contacts"),
        perm(7, "Case notes", "annotation", "Parent", ["Authenticated Users"],
             read=True, write=True, create=True, delete=True, append=True,
             parent_id=_id(106), parent_relationship="Incident_Annotation"),
        perm(8, "Case queue", "incident", "Global", ["Case Managers"],
             read=True, write=True, append=True, appendto=True),
        perm(9, "Staff list", "systemuser", "Global", [], read=True),
        perm(10, "Account access", "account", "Account", ["Legacy Public Access"],
             read=True, write=True, account_relationship="contact_customer_accounts"),
    ]

    model.profiles = [
        ColumnPermissionProfile(
            id=_id(201), name="Case editing", table="incident",
            all_permissions=["Read"], roles=["Authenticated Users"], website_id=SITE,
            columns=[ColumnPermission(id=_id(211), column="title",
                                      permissions=["Read", "Update"]),
                     ColumnPermission(id=_id(212), column="description",
                                      permissions=["Read", "Update"])]),
        ColumnPermissionProfile(
            id=_id(202), name="Settings WebAdmin", table="contact",
            all_permissions=["Create", "Read", "Update"],
            roles=["Case Managers"], website_id=SITE),
    ]

    model.webapi = [
        WebApiTable(entity="contact", enabled=True, enabled_raw="true", fields_raw="*",
                    website_id=SITE, enabled_setting_id=_id(301),
                    fields_setting_id=_id(302)),
        WebApiTable(entity="incident", enabled=True, enabled_raw="true",
                    fields_raw="title,ticketnumber,statuscode,description",
                    website_id=SITE, enabled_setting_id=_id(303),
                    fields_setting_id=_id(304)),
    ]
    model.settings = [
        SiteSetting(id=_id(301), name="Webapi/contact/enabled", value="true", website_id=SITE),
        SiteSetting(id=_id(302), name="Webapi/contact/fields", value="*", website_id=SITE),
        SiteSetting(id=_id(303), name="Webapi/incident/enabled", value="true", website_id=SITE),
        SiteSetting(id=_id(304), name="Webapi/incident/fields",
                    value="title,ticketnumber,statuscode,description", website_id=SITE),
        SiteSetting(id=_id(305), name="Authentication/Registration/OpenRegistrationEnabled",
                    value="true", website_id=SITE),
        SiteSetting(id=_id(306), name="Authentication/Registration/RequiresConfirmation",
                    value="false", website_id=SITE),
    ]

    model.entity_lists = [
        EntityList(id=_id(401), name="Open cases", table="incident", odata_enabled=True,
                   odata_entityset="OpenCases", website_id=SITE,
                   view_fetchxml='<fetch><entity name="incident">'
                                 '<attribute name="title" /></entity></fetch>'),
    ]
    model.entity_forms = [
        EntityForm(id=_id(501), name="Contact us", table="lead", mode="Insert",
                   website_id=SITE),
        EntityForm(id=_id(502), name="Update my details", table="contact", mode="Edit",
                   website_id=SITE),
    ]

    model.templates = [
        WebTemplate(id=_id(601), name="Event lookup", source=EVENT_LOOKUP, website_id=SITE),
        WebTemplate(id=_id(602), name="Product catalogue", source=PRODUCT_CATALOGUE,
                    website_id=SITE),
    ]
    model.page_templates = [
        PageTemplate(id=_id(651), name="Event lookup", web_template_id=_id(601),
                     website_id=SITE),
        PageTemplate(id=_id(652), name="Product catalogue", web_template_id=_id(602),
                     website_id=SITE),
    ]
    model.snippets = [
        ContentSnippet(id=_id(681), name="Footer/Copyright",
                       value="© Contoso Ltd", website_id=SITE),
    ]

    model.publishing_states = [
        PublishingState(id=_id(950), name="Published", is_visible=True,
                        is_default=True, website_id=SITE),
        PublishingState(id=_id(951), name="Draft", is_visible=False, website_id=SITE),
    ]

    def page(n, name, partial, parent=0, **kw):
        kw.setdefault("state_id", _id(950))
        kw.setdefault("state", "Published")
        return WebPage(id=_id(700 + n), name=name, title=name, partial_url=partial,
                       parent_id=_id(700 + parent) if parent else "",
                       website_id=SITE, is_root=True, **kw)

    model.pages = [
        page(1, "Home", "/"),
        page(2, "Products", "products", 1, page_template_id=_id(652)),
        page(3, "Events", "events", 1),
        page(4, "Registration", "registration", 3, page_template_id=_id(651)),
        page(5, "Speakers", "speakers", 3, copy=SPEAKERS),
        page(6, "Store locator", "stores", 1, custom_js=STORE_LOCATOR_JS),
        page(7, "Contact us", "contact-us", 1, entity_form_id=_id(501)),
        page(8, "My cases", "my-cases", 1, entity_list_id=_id(401)),
        page(9, "Case detail", "detail", 8),
        page(10, "My profile", "profile", 1, entity_form_id=_id(502)),
        page(11, "Blog", "blog", 1),
        page(12, "Old staff directory", "staff-directory"),
        page(13, "Speaker contact sheet", "speaker-contacts", 3, copy=SPEAKERS,
             state_id=_id(951), state="Draft", live=False),
    ]
    model.resolve_page_paths()

    pages = {p.id: p for p in model.pages}
    model.page_rules = [
        PageAccessRule(id=_id(801), name="Signed-in customers only", right="RestrictRead",
                       scope="All content", page_id=_id(708),
                       page_name=f"My cases ({pages[_id(708)].path})",
                       roles=["Authenticated Users"], website_id=SITE),
    ]
    model.files = [
        WebFile(id=_id(901), name="price-list.pdf", partial_url="price-list.pdf",
                parent_page_id=_id(702), website_id=SITE),
        WebFile(id=_id(902), name="case-handling-guide.pdf",
                partial_url="case-handling-guide.pdf",
                parent_page_id=_id(708), website_id=SITE),
    ]
    return model


# --- stand-ins for the network ------------------------------------------------


class DemoClient:
    """Answers the few calls the audit makes beyond reading configuration."""

    org_url = ORG

    def detect_schemas(self):
        return [("adx", CONFIG_SCHEMAS["adx"])]

    def portal_solutions(self):
        return [
            {"uniquename": "CDSBasePortal", "friendlyname": "Portal Base",
             "version": "9.3.2405.10"},
            {"uniquename": "MicrosoftPortalBase", "friendlyname": "Portal Base Theme",
             "version": "9.3.2205.12"},
            {"uniquename": "MicrosoftPortalCommunity",
             "friendlyname": "Community Portal", "version": "9.3.2206.4"},
        ]


def _fake_url_probes(urls, **_):
    gated = ("/my-cases",)
    out = {}
    for url in dict.fromkeys(urls):
        path = url[len(PORTAL):] or "/"
        if path.startswith(gated):
            out[url] = pageprobe.ProbeResult(url, 200, pageprobe.GATED,
                                             "/SignIn?returnUrl=" + path)
        # A draft page is not served, which is what the publishing state is for.
        elif "speaker-contacts" in path or "staff-directory" in path:
            out[url] = pageprobe.ProbeResult(url, 404, pageprobe.NOT_FOUND, path)
        else:
            out[url] = pageprobe.ProbeResult(url, 200, pageprobe.OPEN, path)
    return out


def _fake_endpoint_probes(urls, **_):
    verdicts = {
        "/_odata/$metadata": (200, pageprobe.EMPTY, "answered anonymously"),
        "/_api/contacts": (200, pageprobe.LEAK, "rows returned to an anonymous caller"),
        "/_odata/contacts": (404, pageprobe.UNAVAILABLE,
                             "OData EntitySet API is disabled for this site"),
        "/_api/incidents": (403, pageprobe.DENIED,
                            "read not permitted for an anonymous caller"),
        "/_odata/incidents": (404, pageprobe.UNAVAILABLE,
                              "OData EntitySet API is disabled for this site"),
    }
    out = {}
    for url in dict.fromkeys(urls):
        status, verdict, note = verdicts.get(url[len(PORTAL):],
                                             (404, pageprobe.NOT_FOUND, "no such entity set"))
        out[url] = pageprobe.EndpointResult(url, status, verdict, note)
    return out


# --- build ----------------------------------------------------------------------


def build_report() -> Report:
    model = build_model()
    report = Report(target=PORTAL, started="2026-09-15T02:30:00+00:00")
    report.context.update({
        "instance": "Contoso Community Portal (Demo)",
        "portal_url": PORTAL,
        "dataverse_url": ORG,
        "whoami": "a1b2c3d4-0000-4000-8000-00000000abcd",
        "entity_sets_map": {"contact": "contacts", "incident": "incidents"},
    })

    # Outside-in: what the scanner would have recorded against this site.
    scanner = AnonScanner(PORTAL)
    report.add(Finding(
        Severity.MEDIUM, "OData $metadata is anonymously readable",
        detail=("The portal's full table/column schema is exposed to unauthenticated "
                "callers, giving an attacker a map of every entity set to target."),
        source="anon-odata", evidence={"tables_in_metadata": 6}))
    report.context["discovered_tables"] = ["contacts", "incidents", "products"]
    scanner._record([
        ProbeResult(table="contacts", surface="api", reachable=True, whole_table=True,
                    row_seen=True, count=4812, status=200,
                    exposed_columns=["address1_city", "emailaddress1", "fullname",
                                     "mobilephone", "telephone1"]),
        ProbeResult(table="incidents", surface="api", status=403, error_code="90040101"),
    ], report)

    # Inside-out: the real audit over the fictional configuration.
    audit_module.ConfigLoader = lambda client, gen, cfg: _Loaded(model)
    DataverseAudit(DemoClient(), portal_url=PORTAL, check_versions=False).run(report)
    report.context["portal_version"] = "9.3.2405.10"
    report.context["portal_version_source"] = "CDSBasePortal solution"
    report.context["published_release"] = {
        "version": "9.8.8.x", "released": "2026-08-01",
        "source": "https://learn.microsoft.com/power-platform/released-versions/portals/"}

    # Live probes, answered by the stand-ins above.
    pageprobe.probe_urls = _fake_url_probes
    pageprobe.probe_endpoints = _fake_endpoint_probes
    cli._probe_published(report, PORTAL)
    return report


class _Loaded:
    def __init__(self, model):
        self.model = model

    def load(self):
        return self.model


def main() -> None:
    report = build_report()
    for suffix, render in ((".html", report.to_html), (".md", report.to_markdown),
                           (".json", report.to_json)):
        path = HERE / f"sample_report{suffix}"
        path.write_text(render(), encoding="utf-8")
        print(f"wrote {path.relative_to(HERE.parent)}")
    print(report.counts())


if __name__ == "__main__":
    main()
