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


# --- published resource URLs -------------------------------------------------


def test_published_pages_build_absolute_clickable_urls():
    from ppaudit.model import WebPage

    model = build_model(pages=[
        WebPage(id="root", name="Home", partial_url=""),
        WebPage(id="leaf", name="Contact", partial_url="contact-us", parent_id="root"),
    ])
    model.resolve_page_paths()
    urls = {r.name: r.url for r in model.published_pages("https://portal.example/")}
    assert urls["Contact"] == "https://portal.example/contact-us"
    assert urls["Home"] == "https://portal.example/"


def test_published_pages_prefer_title_and_fall_back_to_path_only():
    from ppaudit.model import WebPage

    model = build_model(pages=[WebPage(id="p", name="record name",
                                       title="Nice title", partial_url="x")])
    model.resolve_page_paths()
    r = model.published_pages()[0]           # no base url
    assert r.name == "Nice title"
    assert r.url == "/x"                      # site-relative, still usable


def test_published_files_hang_off_their_parent_page_path():
    from ppaudit.model import WebFile, WebPage

    model = build_model(pages=[
        WebPage(id="docs", name="Docs", partial_url="docs"),
    ], files=[
        WebFile(id="f1", name="guide.pdf", partial_url="guide.pdf", parent_page_id="docs"),
        WebFile(id="f2", name="root.css", partial_url="/root.css"),
    ])
    model.resolve_page_paths()
    urls = {r.name: r.url for r in model.published_files("https://portal.example")}
    assert urls["guide.pdf"] == "https://portal.example/docs/guide.pdf"
    assert urls["root.css"] == "https://portal.example/root.css"


def test_language_variants_collapse_to_one_row_per_root_page():
    from ppaudit.model import WebPage

    model = build_model(pages=[
        WebPage(id="root", name="About", partial_url="about", is_root=True),
        WebPage(id="en", name="About (en)", partial_url="about", root_page_id="root"),
        WebPage(id="mi", name="About (mi)", partial_url="about", root_page_id="root"),
    ])
    model.resolve_page_paths()
    rows = model.published_pages("https://portal.example")
    assert len(rows) == 1                       # not three
    assert rows[0].url == "https://portal.example/about"
    assert "2 languages" in rows[0].name        # two content pages = two languages


def test_orphan_pages_are_flagged_and_home_is_not():
    from ppaudit.model import WebPage

    model = build_model(pages=[
        WebPage(id="home", name="Home", partial_url="", is_root=True),
        WebPage(id="child", name="Team", partial_url="team", parent_id="home", is_root=True),
        WebPage(id="loose", name="Hidden", partial_url="hidden", is_root=True),
        WebPage(id="broken", name="Broken", partial_url="broken",
                parent_id="gone", is_root=True),
    ])
    model.resolve_page_paths()
    flagged = {r.name: r.orphan for r in model.published_pages()}
    assert flagged["Home"] is False             # no parent, but it is the home page
    assert flagged["Team"] is False             # parented under home
    assert flagged["Hidden"] is True            # no parent, not home
    assert flagged["Broken"] is True            # parent record is missing


def test_detached_language_variant_is_surfaced_as_an_orphan():
    """A content page whose root page is gone is reachable but belongs to nothing."""
    from ppaudit.model import WebPage

    model = build_model(pages=[
        WebPage(id="home", name="Home", partial_url="", is_root=True),
        WebPage(id="live-root", name="Products", partial_url="products", is_root=True,
                parent_id="home"),
        WebPage(id="live-en", name="Products en", partial_url="products",
                root_page_id="live-root"),
        # its root record no longer exists in the page set:
        WebPage(id="ghost-en", name="Old promo", partial_url="old-promo",
                root_page_id="deleted-root"),
    ])
    model.resolve_page_paths()
    rows = {r.path: r for r in model.published_pages()}
    assert rows["/products"].orphan is False          # live root, variant collapsed
    assert "languages" not in rows["/products"].name  # one content page = one language
    assert rows["/old-promo"].orphan is True          # detached variant surfaced
    assert "detached variant" in rows["/old-promo"].name
