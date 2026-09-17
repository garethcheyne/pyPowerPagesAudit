"""Summary qualifiers: what bounds a finding, read off the recorded evidence."""

from __future__ import annotations

from ppaudit.report import Finding, Severity


def _finding(**evidence) -> Finding:
    return Finding(Severity.HIGH, "t", source="dataverse:adx", evidence=evidence)


def test_a_queryable_table_says_so():
    assert "queryable on /_api" in _finding(channel="queryable").qualifiers


def test_a_render_only_page_says_it_is_not_on_the_api():
    quals = _finding(channel="page render (server-side)",
                     query_constraints="(none detected)").qualifiers
    assert quals[0] == "not on /_api, page render only"
    assert "no filter in the query" in quals


def test_a_fetchxml_filter_is_reported_as_mitigation():
    quals = _finding(channel="page render (server-side)",
                     query_constraints="FetchXML <filter>, FetchXML <condition>").qualifiers
    assert "bounded by a FetchXML filter" in quals


def test_visitor_input_outranks_any_filter():
    """A query the visitor steers is not bounded, however many filters it has."""
    quals = _finding(query_constraints="FetchXML <filter>",
                     visitor_controlled_input=True).qualifiers
    assert "query steered by request input" in quals
    assert not any("bounded" in q for q in quals)


def test_an_external_observation_is_marked_confirmed():
    scan = Finding(Severity.CRITICAL, "t", source="anon-api", evidence={"surface": "api"})
    assert scan.qualifiers[0] == "confirmed from the internet"
    assert _finding(channel="proven").qualifiers[0] == "confirmed from the internet"


def test_write_channels_are_named():
    assert "writable on /_api" in _finding(write_channel="api").qualifiers
    assert "reachable through a form" in _finding(write_channel="form").qualifiers
    assert "nothing writes to it today" in _finding(write_channel="none").qualifiers


def test_a_fields_wildcard_is_called_out():
    assert "every column published" in _finding(
        channel="queryable", webapi_fields="*").qualifiers


def test_no_evidence_means_no_qualifiers():
    assert Finding(Severity.LOW, "t").qualifiers == []


def test_at_most_three_are_shown():
    quals = _finding(channel="queryable", query_constraints="(none detected)",
                     write_channel="api", webapi_fields="*").qualifiers
    assert len(quals) == 3


# --- what a finding is about --------------------------------------------------


def test_a_table_finding_is_about_its_table():
    assert Finding(Severity.HIGH, "t", table="contact").subject == "contact"


def test_a_site_setting_names_itself_and_its_value():
    """Several settings share one title; the line must say which and what."""
    finding = Finding(Severity.MEDIUM, "Site setting weakens the security posture",
                      evidence={"setting": "Authentication/Registration/"
                                           "OpenRegistrationEnabled",
                                "value": "true", "impact": "anyone can self-register"})
    assert finding.subject == ("Authentication/Registration/OpenRegistrationEnabled "
                               "= true")
    assert finding.qualifiers[0] == "anyone can self-register"


def test_two_settings_findings_are_distinguishable():
    def setting(name, value, impact):
        return Finding(Severity.MEDIUM, "Site setting weakens the security posture",
                       evidence={"setting": name, "value": value, "impact": impact})

    a = setting("Authentication/Registration/OpenRegistrationEnabled", "true",
                "anyone can self-register")
    b = setting("Authentication/Registration/RequiresConfirmation", "false",
                "email addresses go unverified")
    assert a.subject != b.subject
    assert a.qualifiers != b.qualifiers


def test_a_role_finding_names_the_role():
    finding = Finding(Severity.HIGH, "One web role serves both audiences",
                      evidence={"role": "Legacy Public Access", "table_permissions": 3})
    assert finding.subject == "Legacy Public Access"


def test_subject_is_empty_when_nothing_identifies_it():
    assert Finding(Severity.INFO, "t").subject == ""


# --- the mitigation badge ----------------------------------------------------


def test_a_filtered_render_only_query_reads_as_mitigated():
    assert _finding(channel="page render (server-side)",
                    query_constraints="FetchXML <filter>").mitigation == \
        ("Mitigated", "ok")


def test_an_unfiltered_render_only_query_is_only_partly_mitigated():
    assert _finding(channel="page render (server-side)",
                    query_constraints="(none detected)").mitigation == \
        ("Partly mitigated", "partial")


def test_an_open_api_channel_is_not_mitigated():
    assert _finding(channel="queryable").mitigation == ("Not mitigated", "open")
    assert _finding(write_channel="api").mitigation == ("Not mitigated", "open")


def test_visitor_steerable_is_not_mitigated_despite_a_filter():
    assert _finding(query_constraints="FetchXML <filter>",
                    visitor_controlled_input=True).mitigation == \
        ("Not mitigated", "open")


def test_an_external_observation_is_confirmed_exposed():
    scan = Finding(Severity.CRITICAL, "t", source="anon-api", evidence={"surface": "api"})
    assert scan.mitigation == ("Confirmed exposed", "open")


def test_a_correlated_leak_is_confirmed_exposed():
    """It exists because the scanner read the table, so it is never unlabelled."""
    correlated = Finding(Severity.CRITICAL, "External leak tied to configured permissions",
                         table="contacts", source="correlation",
                         evidence={"root_cause_permissions": 1,
                                   "anonymous_roles": "Anonymous Users"})
    assert correlated.mitigation == ("Confirmed exposed", "open")
    assert "confirmed from the internet" in correlated.qualifiers


def test_a_permission_nothing_exercises_is_mitigated():
    assert _finding(write_channel="none").mitigation == ("Mitigated", "ok")


def test_silence_when_the_evidence_does_not_say():
    assert Finding(Severity.LOW, "t").mitigation == ("", "")


def test_the_summary_shows_the_badge_and_links_the_page():
    from ppaudit import htmlreport
    from ppaudit.report import Report

    report = Report(target="https://portal.example")
    report.add(Finding(Severity.HIGH, "Unprotected page renders data", table="contact",
                       source="dataverse:adx",
                       evidence={"url": "https://portal.example/speakers",
                                 "channel": "page render (server-side)",
                                 "query_constraints": "FetchXML <filter>"}))
    html = htmlreport._summary(report)
    assert "mit-ok" in html and "Mitigated" in html
    assert 'href="https://portal.example/speakers"' in html
    assert "bounded by a FetchXML filter" in html
