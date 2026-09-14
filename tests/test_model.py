"""Configuration model: page hierarchy, permission inheritance, record links."""

from __future__ import annotations

from helpers import build_model, page, permission, role, rule


def test_page_paths_resolve_through_the_parent_chain():
    model = build_model(pages=[
        page("root", "Home", ""),
        page("mid", "Section", "docs", parent="root"),
        page("leaf", "Article", "intro", parent="mid"),
    ])
    model.resolve_page_paths()
    assert {p.id: p.path for p in model.pages}["leaf"] == "/docs/intro"


def test_page_paths_survive_a_cycle():
    model = build_model(pages=[
        page("a", "A", "a", parent="b"),
        page("b", "B", "b", parent="a"),
    ])
    model.resolve_page_paths()  # must terminate
    assert all(p.path.startswith("/") for p in model.pages)


# --- page permission inheritance --------------------------------------------


def test_page_with_its_own_restrict_read_is_protected():
    model = build_model(pages=[page("p", "Members", "members")],
                        page_rules=[rule("lock", "p", roles=["Members"])])
    assert model.protecting_rules("p")


def test_child_page_inherits_the_parent_rule():
    """Rules cascade; checking only the page itself would call this public."""
    model = build_model(
        pages=[page("parent", "Members", "members"),
               page("child", "Detail", "detail", parent="parent")],
        page_rules=[rule("lock", "parent", roles=["Members"])])
    assert model.protecting_rules("child")


def test_unprotected_page_reports_no_rules():
    model = build_model(pages=[page("p", "Public", "public")])
    assert model.protecting_rules("p") == []


def test_grant_change_rule_does_not_count_as_read_protection():
    model = build_model(
        pages=[page("p", "Page", "page")],
        page_rules=[rule("edit", "p", right="Grant Change", roles=["Editors"])])
    assert model.protecting_rules("p") == []


def test_protecting_rules_survives_a_cycle():
    model = build_model(pages=[page("a", "A", "a", parent="b"),
                               page("b", "B", "b", parent="a")])
    assert model.protecting_rules("a") == []


# --- record links ------------------------------------------------------------


def test_record_url_singularises_the_entity_set():
    model = build_model()
    url = model.record_url("entitypermission", "abc-123")
    assert "etn=adx_entitypermission&id=abc-123" in url
    assert "pagetype=entityrecord" in url


def test_record_url_is_empty_without_an_id():
    assert build_model().record_url("entitypermission", "") == ""


def test_record_url_is_empty_for_an_unknown_key():
    assert build_model().record_url("nonexistent", "abc") == ""


# --- content sources ---------------------------------------------------------


def test_content_sources_carry_page_id_and_both_links(model):
    sources = model.content_sources("https://portal.example")
    public = next(s for s in sources if s.name == "Public API")
    assert public.page_id == "page-pub"
    assert public.url == "https://portal.example/api"
    assert "etn=adx_webpage" in public.record_url


def test_in_use_detects_an_empty_generation():
    empty = build_model(websites=[])
    assert empty.in_use is False
    assert build_model().in_use is True          # a website record is real config
    assert build_model(websites=[], roles=[role("Anonymous", anon=True)]).in_use is True


def test_webapi_and_profile_lookups_are_case_insensitive(model):
    assert model.webapi_for("CONTACT") is not None
    assert model.profiles_for("CONTACT")


def test_permissions_for_role(model):
    assert len(model.permissions_for_role("Anonymous")) == 2


def test_privileges_reports_only_what_is_granted():
    perm = permission("p", "contact", "Self", read=True, write=True, append=True)
    assert perm.privileges() == ["Read", "Write", "Append"]
    assert perm.mutating == ["Write"]
