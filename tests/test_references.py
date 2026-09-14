"""Reference scanning: finding where a table is rendered, and scoping columns."""

from __future__ import annotations

from ppaudit.references import ContentSource, ReferenceIndex

FETCH_PAGE = """
{% fetchxml staff %}
  <fetch>
    <entity name="systemuser">
      <attribute name="internalemailaddress" />
      <attribute name="fullname" />
    </entity>
  </fetch>
{% endfetchxml %}

{% fetchxml catalogue %}
  <fetch>
    <entity name="product">
      <attribute name="name" />
    </entity>
  </fetch>
{% endfetchxml %}
"""


def index(text, **kwargs):
    return ReferenceIndex([ContentSource(kind="Web page copy", name="Page",
                                         text=text, **kwargs)])


def test_finds_fetchxml_entity():
    hits = index(FETCH_PAGE).find("systemuser")
    assert hits and hits[0].how == "FetchXML <entity>"


def test_columns_do_not_bleed_between_query_blocks():
    """The killer false positive: product must not inherit the staff columns."""
    staff = index(FETCH_PAGE).find("systemuser", ["internalemailaddress", "name"])
    product = index(FETCH_PAGE).find("product", ["internalemailaddress", "name"])
    assert "internalemailaddress" in staff[0].columns
    assert "internalemailaddress" not in product[0].columns
    assert "name" in product[0].columns


def test_link_entity_is_recognised():
    text = '<fetch><entity name="quote"><link-entity name="systemuser" /></entity></fetch>'
    assert index(text).find("systemuser")[0].how == "FetchXML <link-entity>"


def test_liquid_entities_lookup():
    assert index("{% assign s = entities['systemuser'][id] %}").find("systemuser")


def test_web_api_call_in_page_script():
    hits = index('$.get("/_api/contacts?$select=emailaddress1")').find(
        "contact", ["emailaddress1"])
    assert hits and "emailaddress1" in hits[0].columns


def test_unrelated_table_is_not_matched():
    assert index(FETCH_PAGE).find("account") == []


def test_one_hit_per_line_not_per_pattern():
    text = '<fetch><entity name="contact" /></fetch>'
    assert len(index(text).find("contact")) == 1


def test_reference_carries_both_links_and_the_page_id():
    src = ContentSource(kind="Web page copy", name="API", text=FETCH_PAGE,
                        url="https://example.com/api", record_url="https://crm/rec",
                        page_id="page-1")
    ref = ReferenceIndex([src]).find("systemuser")[0]
    assert ref.url == "https://example.com/api"
    assert ref.config_url == "https://crm/rec"
    assert ref.page_id == "page-1"


def test_snippet_is_single_line_and_bounded():
    snippet = index(FETCH_PAGE).find("systemuser")[0].snippet
    assert "\n" not in snippet
    assert len(snippet) < 200


def test_empty_table_name_is_ignored():
    assert index(FETCH_PAGE).find("") == []


# --- constraint detection ----------------------------------------------------


def test_unfiltered_query_reports_no_constraints():
    text = '<fetch><entity name="contact" /></fetch>'
    ref = index(text).find("contact")[0]
    assert ref.constraints == []
    assert ref.constrained is False


def test_filter_and_condition_are_detected():
    text = ('<fetch><entity name="contact">'
            '<filter><condition attribute="statecode" operator="eq" value="0" />'
            '</filter></entity></fetch>')
    ref = index(text).find("contact")[0]
    assert "FetchXML <filter>" in ref.constraints
    assert "FetchXML <condition>" in ref.constraints
    assert ref.constrained is True


def test_row_limit_counts_as_a_constraint():
    text = '<fetch count="10"><entity name="contact" /></fetch>'
    assert "row limit" in index(text).find("contact")[0].constraints


def test_request_parameters_mark_the_query_visitor_steerable():
    text = ('<fetch><entity name="contact"><filter><condition value="'
            "{{ request.params['id'] }}\" /></filter></entity></fetch>")
    ref = index(text).find("contact")[0]
    assert ref.visitor_input is True
    assert ref.constrained is False      # a filter the visitor controls is not a bound


def test_constraints_do_not_leak_between_blocks():
    """A filter on one query must not vouch for an unfiltered query beside it."""
    text = (
        '{% fetchxml a %}<fetch><entity name="contact">'
        '<filter><condition attribute="statecode" /></filter>'
        "</entity></fetch>{% endfetchxml %}\n"
        '{% fetchxml b %}<fetch><entity name="account" /></fetch>{% endfetchxml %}'
    )
    assert index(text).find("contact")[0].constrained is True
    assert index(text).find("account")[0].constrained is False
