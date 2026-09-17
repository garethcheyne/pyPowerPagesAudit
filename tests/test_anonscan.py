"""The anonymous scanner: address handling, and not mistaking silence for safety."""

from __future__ import annotations

from ppaudit.anonscan import AnonScanner, ProbeResult
from ppaudit.report import Report, Severity

normalize = AnonScanner.normalize_url


def test_www_is_preserved():
    """Dropping it breaks TLS on sites served only under www."""
    assert normalize("https://www.contoso.example") == "https://www.contoso.example"
    assert normalize("www.contoso.example") == "https://www.contoso.example"


def test_scheme_is_added_and_trailing_slash_removed():
    assert normalize("contoso.powerappsportals.com/") == "https://contoso.powerappsportals.com"
    assert normalize("http://contoso.example/") == "http://contoso.example"


def test_a_host_containing_www_is_not_rewritten():
    assert normalize("https://wwwtest.contoso.example") == "https://wwwtest.contoso.example"


def _record(results):
    scanner = AnonScanner("https://www.contoso.example")
    report = Report(target=scanner.url)
    scanner._record(results, report)
    return report


def test_probes_that_never_connected_are_reported_not_passed():
    report = _record([
        ProbeResult(table="contacts", surface="api", error="SSLError(...)"),
        ProbeResult(table="contacts", surface="odata", error="SSLError(...)"),
    ])
    titles = [f.title for f in report.findings]
    assert "Anonymous scan could not reach the site" in titles
    assert "No anonymously readable tables found" not in titles
    assert max(f.severity for f in report.findings) is Severity.HIGH
    assert report.context["scan_unanswered"] == 2


def test_a_site_that_answers_and_exposes_nothing_is_clean():
    report = _record([ProbeResult(table="contacts", surface="api", status=403)])
    assert [f.title for f in report.findings] == ["No anonymously readable tables found"]
    assert report.context["anon_exposed_tables"] == []


def test_a_clean_result_states_how_much_was_covered():
    """'Nothing found' means little without how much was asked."""
    report = _record([
        ProbeResult(table="contacts", surface="api", status=404),
        ProbeResult(table="contacts", surface="odata", status=404),
        ProbeResult(table="accounts", surface="api", error="timeout"),
    ])
    finding = report.findings[0]
    assert finding.evidence == {"tables_probed": 2, "probes_answered": 2,
                                "probes_unanswered": 1}
    assert "untested rather than confirmed closed" in finding.detail


def test_rows_returned_anonymously_are_critical():
    report = _record([ProbeResult(table="contacts", surface="api", status=200,
                                  reachable=True, whole_table=True, row_seen=True,
                                  count=4812, exposed_columns=["emailaddress1"])])
    assert report.findings[0].severity is Severity.CRITICAL
    assert report.context["anon_exposed_tables"] == ["contacts"]
