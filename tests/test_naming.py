"""Naming convention: codes, chains, disambiguation and truncation."""

from __future__ import annotations

import pytest

from ppaudit import naming
from helpers import build_model, permission, role


def test_privilege_code_orders_consistently():
    assert naming.privilege_code(["Write", "Read"]) == "R/W"
    assert naming.privilege_code(["AppendTo", "Append", "Read"]) == "R/A/A2"
    assert naming.privilege_code([]) == "none"


def test_column_permission_code():
    assert naming.column_permission_code(["Update", "Read"]) == "R/U"
    assert naming.column_permission_code([]) == "none"


def test_validate_template_rejects_unknown_placeholder():
    with pytest.raises(naming.NamingError) as exc:
        naming.validate_template("{nope}")
    assert "nope" in str(exc.value)


def test_validate_template_scopes_to_the_record_kind():
    naming.validate_template("{columns_flag}", naming.PROFILE_PLACEHOLDERS)
    with pytest.raises(naming.NamingError):
        naming.validate_template("{columns_flag}")  # not a permission placeholder


def test_build_name_collapses_whitespace_and_truncates():
    name = naming.build_name("{table}   [{privileges}]", table="contact",
                             scope="Self", privileges=["Read"], roles=[],
                             website="", current="", max_name=12)
    assert name == "contact [R]"


# --- parent chain ------------------------------------------------------------


def test_resolve_chain_follows_parents_to_the_effective_scope():
    child = permission("notes", "annotation", "Parent", pid="p1", parent_id="p2")
    parent = permission("cases", "incident", "Account", pid="p2")
    by_id = {"p1": child, "p2": parent}
    assert naming.resolve_chain(child, by_id) == ("Account", "Parent>Account")


def test_resolve_chain_handles_depth():
    a = permission("a", "annotation", "Parent", pid="p1", parent_id="p2")
    b = permission("b", "adx_portalcomment", "Parent", pid="p2", parent_id="p3")
    c = permission("c", "incident", "Contact", pid="p3")
    root, chain = naming.resolve_chain(a, {"p1": a, "p2": b, "p3": c})
    assert root == "Contact"
    assert chain == "Parent>Parent>Contact"


def test_resolve_chain_survives_a_cycle():
    a = permission("a", "contact", "Parent", pid="p1", parent_id="p2")
    b = permission("b", "account", "Parent", pid="p2", parent_id="p1")
    # Must terminate rather than loop forever.
    assert naming.resolve_chain(a, {"p1": a, "p2": b}) == ("Parent", "Parent>Parent")


def test_resolve_chain_without_a_parent_is_the_scope_itself():
    solo = permission("solo", "contact", "Self", pid="p1")
    assert naming.resolve_chain(solo, {"p1": solo}) == ("Self", "Self")


# --- anonymous marker --------------------------------------------------------


def test_anon_marker_applied_only_to_anonymous_bindings():
    model = build_model(
        roles=[role("Anonymous", anon=True), role("Staff")],
        permissions=[permission("pub", "adx_blogpost", "Global", roles=["Anonymous"]),
                     permission("priv", "contact", "Self", roles=["Staff"])])
    proposed = {r.table: r.proposed for r in naming.plan(model).renames}
    assert proposed["adx_blogpost"].endswith(naming.ANON_MARKER)
    assert naming.ANON_MARKER not in proposed["contact"]


def test_anon_marker_survives_truncation():
    """The flag must never be the part that gets cut off a long name."""
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "a_very_long_table_name_indeed", "Global",
                                roles=["Anonymous"])])
    plan = naming.plan(model, max_name=30)
    proposed = plan.renames[0].proposed
    assert len(proposed) <= 30
    assert proposed.endswith(naming.ANON_MARKER)


def test_anon_marker_does_not_stack_on_repeat_runs():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "adx_ad", "Global", roles=["Anonymous"])])
    first = naming.plan(model).renames[0].proposed
    model.permissions[0].name = first
    second = naming.plan(model).renames[0].proposed
    assert second == first
    assert second.count(naming.ANON_MARKER) == 1


def test_anon_marker_can_be_disabled():
    model = build_model(
        roles=[role("Anonymous", anon=True)],
        permissions=[permission("p", "adx_ad", "Global", roles=["Anonymous"])])
    assert naming.ANON_MARKER not in naming.plan(model, anon_marker="").renames[0].proposed


# --- disambiguation ----------------------------------------------------------


def test_collision_resolves_by_parent_chain_not_by_role():
    """Two Parent-scoped grants differing only by chain must stay distinguishable."""
    model = build_model(
        roles=[role("A"), role("B")],
        permissions=[
            permission("self notes", "annotation", "Parent", pid="p1",
                       parent_id="r1", roles=["A"]),
            permission("account notes", "annotation", "Parent", pid="p2",
                       parent_id="r2", roles=["B"]),
            permission("cases self", "incident", "Contact", pid="r1", roles=["A"]),
            permission("cases account", "incident", "Account", pid="r2", roles=["B"]),
        ])
    names = sorted(r.proposed for r in naming.plan(model).renames
                   if r.table == "annotation")
    assert names == ["annotation [R] (Parent>Account)", "annotation [R] (Parent>Contact)"]


def test_role_names_never_appear_in_a_proposed_name():
    model = build_model(
        roles=[role("Deliver Agent"), role("Web Admin")],
        permissions=[permission("one", "contact", "Self", roles=["Deliver Agent"]),
                     permission("two", "contact", "Self", roles=["Web Admin"])])
    for rename in naming.plan(model).renames:
        assert "Agent" not in rename.proposed
        assert "Admin" not in rename.proposed


def test_identical_grants_fall_through_to_a_counter_and_say_why():
    model = build_model(
        roles=[role("A"), role("B")],
        permissions=[permission("one", "contact", "Self", roles=["A"]),
                     permission("two", "contact", "Self", roles=["B"])])
    renames = naming.plan(model).renames
    assert sorted(r.proposed for r in renames) == [
        "contact [R] (Self) #1", "contact [R] (Self) #2"]
    assert all("differ only by role binding" in r.reason for r in renames)


def test_proposed_names_are_unique():
    model = build_model(
        roles=[role("A"), role("B"), role("C")],
        permissions=[permission(f"p{i}", "contact", "Self", roles=[r])
                     for i, r in enumerate("ABC")])
    proposed = [r.proposed for r in naming.plan(model).renames]
    assert len(set(proposed)) == len(proposed)


# --- column permission profiles ---------------------------------------------


def test_profile_names_describe_the_all_column_default(model):
    proposed = {r.table: r.proposed for r in naming.plan_profiles(model).renames}
    assert proposed["contact"] == "contact [all:R/U] +columns"
    assert proposed["incident"] == "incident [all:C/R/U]"


def test_profile_plan_targets_the_profile_entity_set(model):
    plan = naming.plan_profiles(model)
    assert plan.entity_set == "adx_columnpermissionprofiles"
    assert plan.name_field == "adx_profilename"
    assert plan.kind == "column permission profile"
