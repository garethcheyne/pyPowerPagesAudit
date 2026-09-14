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
