"""Documentation references and report rendering."""

from __future__ import annotations

import pytest

from helpers import sample_model

from ppaudit import docs
from ppaudit.report import Finding, Report, Severity


# --- Learn references --------------------------------------------------------


def test_every_link_is_locale_neutral():
    """/en-us/ in the path would force English on every reader."""
    for link in docs.iter_links():
        assert "/en-us/" not in link.url
        assert link.url.startswith("https://learn.microsoft.com/")


def test_every_link_has_a_title():
    assert all(link.title.strip() for link in docs.iter_links())


def test_finding_titles_the_audit_emits_resolve_to_docs():
    emitted = [
        "Anonymous global read of a table",
        "Anonymous data modification permitted",
        "Anonymous read with Self scope",          # parameterised, prefix match
        "Web API publishes every column of a table",
        "One web role serves both anonymous and signed-in users",
        "Table permission bound to no web role",
        "Entity list publishes an OData feed",
        "Site setting weakens the security posture",
        # The page/permission/content join, and the rest of the security findings.
        "Unprotected page renders anonymously-readable data",
        "Unpublished pages would expose data once published",
        "Form on an unprotected page writes to a table",
        "Published files are publicly reachable",
        "Column permission profile bound to an anonymous role",
        "Column permission profile bound to no web role",
        "Power Pages solutions are behind the rest of the environment",
        "Standard data model not in use",
        # Scanner titles name their surface, so these exercise the prefix match.
        "Whole table readable anonymously via Web API",
        "Whole table readable anonymously via OData feed",
        "Table endpoint open via Web API (no rows returned now)",
        "Column-level leak via OData feed",
        "OData $metadata is anonymously readable",
    ]
    for title in emitted:
        assert docs.for_finding(title), f"no documentation mapped for {title!r}"


def test_unknown_title_returns_nothing_rather_than_guessing():
    assert docs.for_finding("Something we never emit") == []


@pytest.mark.network
def test_documentation_links_still_resolve():
    """Learn reorganises; this catches rot. Deselect with -m 'not network'."""
    import requests

    for link in docs.iter_links():
        resp = requests.get(link.url, timeout=30)
        assert resp.status_code == 200, f"{link.url} -> {resp.status_code}"


# --- rendering ---------------------------------------------------------------


def _report():
    report = Report(target="https://portal.example")
    report.context.update({"instance": "Contoso", "portal_url": "https://portal.example",
                           "dataverse_url": "https://contoso.crm.dynamics.com"})
    report.models = [sample_model()]
    report.add(Finding(Severity.CRITICAL, "Anonymous global read of a table",
                       table="contact", detail="Reachable at https://portal.example/api",
                       source="dataverse:adx",
                       evidence={"url": "https://portal.example/api"}))
    return report


def test_html_is_self_contained_and_escapes_input():
    report = _report()
    report.add(Finding(Severity.LOW, "<script>alert(1)</script>", table="x"))
    html = report.to_html()
    assert html.startswith("<!DOCTYPE html>")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<link" not in html          # no external stylesheets
    assert 'src="http' not in html      # no external scripts or images


def test_html_linkifies_urls_in_evidence():
    assert 'href="https://portal.example/api"' in _report().to_html()


def test_html_renders_a_localisable_timestamp():
    html = _report().to_html()
    assert '<time class="ts" datetime=' in html


def test_markdown_escapes_pipes_so_tables_survive():
    """Permission names like 'Global | Stores R' must not break the table."""
    from helpers import permission

    report = _report()
    report.models[0].permissions.append(
        permission("Global | Products R", "product", "Global"))
    markdown = report.to_markdown()
    assert "Global \\| Products R" in markdown
    assert "\\\\|" not in markdown           # escaped once, not twice


def test_markdown_links_config_records():
    assert "etn=adx_entitypermission" in _report().to_markdown()


def test_json_round_trips():
    import json
    data = json.loads(_report().to_json())
    assert data["counts"]["Critical"] == 1
    assert data["findings"][0]["table"] == "contact"


def test_console_output_has_no_ansi_when_disabled():
    assert "\033[" not in _report().to_console(color=False)


def test_findings_sort_by_severity_descending():
    report = _report()
    report.add(Finding(Severity.INFO, "Info thing"))
    report.add(Finding(Severity.HIGH, "High thing"))
    severities = [f.severity for f in report.sorted()]
    assert severities == sorted(severities, reverse=True)


def test_html_has_a_published_tab_with_clickable_endpoint_urls():
    from ppaudit.model import WebFile

    report = _report()
    report.models[0].files = [
        WebFile(id="f1", name="brochure.pdf", partial_url="brochure.pdf",
                parent_page_id="page-pub", website_id="site-1")]
    # Endpoint rows come from the anonymous probe, using real entity-set names.
    report.context["endpoint_probes"] = [
        {"table": "contact", "surface": "Web API",
         "url": "https://portal.example/_api/contacts",
         "status": 200, "verdict": "leak", "note": "rows returned"},
        {"table": "metadata", "surface": "OData schema",
         "url": "https://portal.example/_odata/$metadata",
         "status": 404, "verdict": "unavailable",
         "note": "OData EntitySet API is disabled for this site"}]
    html = report.to_html()

    assert 'data-panel="published"' in html          # the tab button
    assert 'id="panel-published"' in html            # the panel
    assert 'href="https://portal.example/_api/contacts"' in html
    assert ">leak<" in html                          # verdict badge from the probe
    assert ">unavailable<" in html                   # OData surface reported off
    assert 'href="https://portal.example/api/brochure.pdf"' in html


def test_published_tab_badges_anonymous_probe_verdicts():
    report = _report()
    pages = report.models[0].published_pages("https://portal.example")
    open_url = next(p.url for p in pages)
    report.context["url_probes"] = {
        open_url: {"status": 200, "verdict": "open", "final_path": "/api/"}}
    html = report.to_html()
    assert '<span class="pill warn"' in html and ">open 200<" in html
    assert "Anonymous probe:" in html          # the per-section tally line
