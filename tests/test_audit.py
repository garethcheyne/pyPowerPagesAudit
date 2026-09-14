"""Severity grading and the page/permission/content join."""

from __future__ import annotations

from helpers import build_model, page, permission, role, rule

from ppaudit.audit import (
    DataverseAudit,
    _anonymous_read_severity,
    _page_exposure_severity,
)
from ppaudit.report import Report, Severity


# --- severity is channel x data class ---------------------------------------


def test_queryable_personal_data_is_critical():
    sev, _ = _anonymous_read_severity("contact", "queryable", True, ["emailaddress1"])
    assert sev is Severity.CRITICAL


def test_externally_proven_is_always_critical():
    sev, _ = _anonymous_read_severity("adx_ad", "proven", False, [])
    assert sev is Severity.CRITICAL


def test_render_only_cms_content_is_informational():
    """The user's point: read-only CMS content with no query channel is by design."""
    sev, _ = _anonymous_read_severity("adx_ad", "render-only", True, [])
    assert sev is Severity.INFO


def test_queryable_cms_content_is_still_low_not_critical():
    sev, _ = _anonymous_read_severity("adx_blogpost", "queryable", True, [])
    assert sev is Severity.LOW


def test_render_only_business_data_is_medium():
    sev, _ = _anonymous_read_severity("product", "render-only", True, [])
    assert sev is Severity.MEDIUM


def test_render_only_personal_data_is_high():
    sev, _ = _anonymous_read_severity("contact", "render-only", True, [])
    assert sev is Severity.HIGH


def test_nothing_renders_it_and_nothing_queries_it_is_low():
    sev, why = _anonymous_read_severity("product", "render-only", False, [])
    assert sev is Severity.LOW
    assert "dormant" in why or "no-one is using" in why


def test_queryable_business_data_is_high():
    sev, _ = _anonymous_read_severity("product", "queryable", True, [])
    assert sev is Severity.HIGH


# --- the join ----------------------------------------------------------------


def _run(model, portal="https://portal.example"):
    audit = DataverseAudit(None, portal_url=portal)
    audit.models = [model]
    report = Report(target=portal)
    sources = model.content_sources(portal)
    from ppaudit.references import ReferenceIndex
    audit._index = ReferenceIndex(sources)
    audit._externally_seen = set()
    audit._analyse_page_exposure(report, model)
    return report


CONTACT_FETCH = ('{% fetchxml q %}<fetch><entity name="contact">'
                 '<attribute name="emailaddress1" /></entity></fetch>{% endfetchxml %}')

FILTERED_FETCH = ('{% fetchxml q %}<fetch><entity name="contact">'
                  '<attribute name="emailaddress1" />'
                  '<filter><condition attribute="statecode" operator="eq" value="0" />'
                  '</filter></entity></fetch>{% endfetchxml %}')

STEERABLE_FETCH = ('{% fetchxml q %}<fetch><entity name="contact">'
                   '<attribute name="emailaddress1" />'
                   '<filter><condition attribute="id" operator="eq" '
                   'value="{{ request.params[\'id\'] }}" /></filter>'
                   '</entity></fetch>{% endfetchxml %}')


# --- a server-side render is not automatically a leak ------------------------


def test_server_side_render_is_never_critical_on_configuration_alone():
    """No Web API means the visitor cannot compose a query; grading must reflect that."""
    sev, _ = _page_exposure_severity(webapi_open=False, steerable=False,
                                     constrained=False, sensitive=True, risky=True)
    assert sev < Severity.HIGH


def test_filtered_server_side_render_is_informational():
    sev, why = _page_exposure_severity(webapi_open=False, steerable=False,
                                       constrained=True, sensitive=False, risky=True)
    assert sev is Severity.INFO
    assert "deliberate" in why


def test_unfiltered_render_of_personal_data_is_medium_not_critical():
    sev, _ = _page_exposure_severity(webapi_open=False, steerable=False,
                                     constrained=False, sensitive=True, risky=True)
    assert sev is Severity.MEDIUM


def test_visitor_steerable_query_is_critical_for_personal_data():
    """Request input turns a render-only page back into a queryable endpoint."""
    sev, _ = _page_exposure_severity(webapi_open=False, steerable=True,
                                     constrained=True, sensitive=True, risky=True)
    assert sev is Severity.CRITICAL


def test_web_api_open_is_critical_for_personal_data():
    sev, _ = _page_exposure_severity(webapi_open=True, steerable=False,
                                     constrained=True, sensitive=True, risky=True)
    assert sev is Severity.CRITICAL


def test_unprotected_page_rendering_personal_data_is_reported_for_review():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Open API", "api", copy=CONTACT_FETCH)])
    model.resolve_page_paths()
    findings = _run(model).findings
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM      # not Critical: no query channel
    assert findings[0].evidence["url"] == "https://portal.example/api"
    assert "emailaddress1" in findings[0].evidence["sensitive_columns"]


def test_a_filtered_query_is_downgraded_and_names_its_filter():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Open API", "api", copy=FILTERED_FETCH)])
    model.resolve_page_paths()
    finding = _run(model).findings[0]
    assert finding.severity is Severity.LOW
    assert "filter" in finding.evidence["query_constraints"].lower()


def test_request_parameters_escalate_a_filtered_query():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Open API", "api", copy=STEERABLE_FETCH)])
    model.resolve_page_paths()
    finding = _run(model).findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["visitor_controlled_input"] is True


def test_protected_page_produces_no_finding():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("locked", "Members", "members", copy=CONTACT_FETCH)],
        page_rules=[rule("lock", "locked", roles=["Members"])])
    model.resolve_page_paths()
    assert _run(model).findings == []


def test_inherited_page_rule_also_suppresses_the_finding():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("parent", "Members", "members"),
               page("child", "Detail", "detail", parent="parent", copy=CONTACT_FETCH)],
        page_rules=[rule("lock", "parent", roles=["Members"])])
    model.resolve_page_paths()
    assert _run(model).findings == []


def test_no_anonymous_permission_means_no_finding():
    model = build_model(
        roles=[role("Members", auth=True)],
        permissions=[permission("p", "contact", "Global", roles=["Members"])],
        pages=[page("pub", "Open", "api", copy=CONTACT_FETCH)])
    model.resolve_page_paths()
    assert _run(model).findings == []


def test_cms_content_on_a_public_page_is_not_reported():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "adx_blogpost", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Blog", "blog",
                    copy='<fetch><entity name="adx_blogpost" /></fetch>')])
    model.resolve_page_paths()
    assert _run(model).findings == []


def test_repeated_reads_on_one_page_collapse_to_a_single_finding():
    repeated = "\n".join([CONTACT_FETCH] * 3)   # find() dedupes per line
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Open API", "api", copy=repeated)])
    model.resolve_page_paths()
    findings = _run(model).findings
    assert len(findings) == 1
    assert findings[0].evidence["occurrences"] >= 2


def test_finding_carries_both_dataverse_records():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "contact", "Global", roles=["Anonymous"])],
        pages=[page("pub", "Open API", "api", copy=CONTACT_FETCH)])
    model.resolve_page_paths()
    evidence = _run(model).findings[0].evidence
    assert "etn=adx_webpage" in evidence["page_record"]
    assert "etn=adx_webpage" in evidence["content_record"]
