"""Proposes self-describing names for table permission records.

``adx_entityname`` is the label a reviewer sees in the Portal Management app
and in this tool's reports. Left to grow organically it ends up as things like
"Read", "Portal access" or "Global | list" — names that say nothing about which
table is affected, what scope applies, or which privileges are granted.
Reviewing security configuration then means opening every record.

A name built from *table + privileges + scope* makes the grant legible at a
glance, and makes the dangerous combinations sort together::

    account [R/W/C/D/A/A2] (Global)
    account [R] (Self)
    contact [R/W] (Self)
Anything bound to an Anonymous Users role is the public internet, so it earns a
trailing marker that survives truncation and sorting::

    adx_blogpost [R] (Global) **ANON**

That marker is the *only* thing role bindings contribute to a name. Which named
roles hold a permission is not a property of the grant, role names drift, and a
permission can carry several — so roles stay out of the name.

``Parent`` scope says nothing on its own — the reach is decided by the parent
table permission it chains to. ``{scope_chain}`` resolves that chain, which is
usually the only thing separating "this contact's notes" from "every note on
the account"::

    annotation [R/W/C/D/A] (Parent>Contact)
    annotation [R/W/C/D/A] (Parent>Account)

The convention is a template, not a rule, because house styles differ. The
default is deliberately machine-sortable rather than prose.

Renaming is proposal-first: :func:`plan` computes what would change and nothing
is written until the caller explicitly applies it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Fallback only. The real limit is read from the target environment, because
# the primary name column is customisable — stock Power Pages ships 100 in some
# versions and 400 in others.
DEFAULT_MAX_NAME = 100

DEFAULT_TEMPLATE = "{table} [{privileges}] ({scope_chain})"

# Column permission profiles answer a different question, so they get their own
# shape: which table, what every *unlisted* column gets by default, and whether
# any columns are listed at all. The "all:" prefix is deliberate — without it
# the codes read as "this profile grants R/U" when they actually mean "anything
# not listed below gets R/U", which is the part that quietly widens as columns
# are added.
#
# Presence of a column list is flagged rather than counted: the count changes
# on every edit, but going from "no list at all" to "has a list" is a real
# change of intent. A profile with no list only applies its all-column default.
DEFAULT_PROFILE_TEMPLATE = "{table} [all:{permissions}] {columns_flag}"

COLUMN_PERMISSION_CODES = [
    ("Create", "C"),
    ("Read", "R"),
    ("Update", "U"),
]

# Flag for permissions reachable without signing in. Appended after templating,
# truncation and deduplication so it can never be the part that gets cut.
ANON_MARKER = "**ANON**"

# Power Pages lists privileges in this order, and A2 for Append To is the
# shorthand already in common use in portal configuration.
PRIVILEGE_CODES = [
    ("Read", "R"),
    ("Write", "W"),
    ("Create", "C"),
    ("Delete", "D"),
    ("Append", "A"),
    ("AppendTo", "A2"),
]

# Compact variant: CRUD run together, relational after a '+'.
COMPACT_CRUD = [("Read", "R"), ("Write", "W"), ("Create", "C"), ("Delete", "D")]
COMPACT_RELATIONAL = [("Append", "a"), ("AppendTo", "t")]

PLACEHOLDERS = {
    "table", "scope", "scope_chain", "root_scope", "parent", "relationship",
    "privileges", "privileges_compact", "privileges_long",
    "roles", "website", "name",
}

PROFILE_PLACEHOLDERS = {
    "table", "permissions", "permissions_long", "columns", "columns_label",
    "columns_flag", "roles", "website", "name",
}


class NamingError(ValueError):
    pass


@dataclass
class Rename:
    """One proposed rename of a table permission record."""

    record_id: str
    generation: str
    table: str
    scope: str
    privileges: list[str]
    roles: list[str]
    current: str
    proposed: str
    anonymous: bool = False
    root_scope: str = ""       # where a Parent chain ultimately resolves
    scope_chain: str = ""
    parent: str = ""
    relationship: str = ""
    website: str = ""
    reason: str = ""

    @property
    def changed(self) -> bool:
        return self.current.strip() != self.proposed

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id, "generation": self.generation,
            "table": self.table, "scope": self.scope,
            "privileges": self.privileges, "roles": self.roles,
            "current": self.current, "proposed": self.proposed,
            "anonymous": self.anonymous,
            "root_scope": self.root_scope, "scope_chain": self.scope_chain,
            "parent": self.parent, "relationship": self.relationship,
            "website": self.website,
            "changed": self.changed, "reason": self.reason,
        }


@dataclass
class Plan:
    template: str
    renames: list[Rename] = field(default_factory=list)
    entity_set: str = ""
    name_field: str = ""
    kind: str = "table permission"
    anon_marker: str = ANON_MARKER
    max_name: int = DEFAULT_MAX_NAME

    @property
    def changes(self) -> list[Rename]:
        return [r for r in self.renames if r.changed]

    @property
    def longest(self) -> int:
        return max((len(r.proposed) for r in self.renames), default=0)

    def to_dict(self) -> dict[str, Any]:
        return {"template": self.template, "entity_set": self.entity_set,
                "name_field": self.name_field, "kind": self.kind,
                "anon_marker": self.anon_marker, "max_name": self.max_name,
                "longest_proposed": self.longest,
                "total": len(self.renames), "changes": len(self.changes),
                "anonymous": sum(1 for r in self.renames if r.anonymous),
                "renames": [r.to_dict() for r in self.renames]}


def privilege_code(privileges: Iterable[str]) -> str:
    """``['Read', 'Append']`` -> ``'R/A'``; no privileges -> ``'none'``."""
    held = {p.lower() for p in privileges}
    codes = [code for name, code in PRIVILEGE_CODES if name.lower() in held]
    return "/".join(codes) or "none"


def privilege_compact(privileges: Iterable[str]) -> str:
    """``['Read', 'Append']`` -> ``'R+a'``; shorter, for tight name fields."""
    held = {p.lower() for p in privileges}
    crud = "".join(c for name, c in COMPACT_CRUD if name.lower() in held)
    rel = "".join(c for name, c in COMPACT_RELATIONAL if name.lower() in held)
    if crud and rel:
        return f"{crud}+{rel}"
    return crud or rel or "none"


def validate_template(template: str, allowed: set[str] | None = None) -> None:
    allowed = allowed or PLACEHOLDERS
    unknown = set(re.findall(r"\{(\w+)\}", template)) - allowed
    if unknown:
        raise NamingError(
            f"Unknown placeholder(s) {', '.join(sorted(unknown))}. "
            f"Available: {', '.join(sorted(allowed))}.")


def column_permission_code(permissions: Iterable[str]) -> str:
    """``['Read', 'Update']`` -> ``'R/U'``; nothing granted -> ``'none'``."""
    held = {p.lower() for p in permissions}
    codes = [code for name, code in COLUMN_PERMISSION_CODES if name.lower() in held]
    return "/".join(codes) or "none"


def build_name(template: str, *, table: str, scope: str, privileges: list[str],
               roles: list[str], website: str, current: str,
               scope_chain: str = "", root_scope: str = "", parent: str = "",
               relationship: str = "", max_name: int = DEFAULT_MAX_NAME) -> str:
    name = template.format(
        table=table or "(unknown table)",
        scope=scope or "unset",
        scope_chain=scope_chain or scope or "unset",
        root_scope=root_scope or scope or "unset",
        parent=parent or "none",
        relationship=relationship or "none",
        privileges=privilege_code(privileges),
        privileges_compact=privilege_compact(privileges),
        privileges_long="/".join(privileges) or "none",
        roles=", ".join(roles) or "unbound",
        website=website,
        name=current,
    )
    name = " ".join(name.split())
    return name[:max_name].rstrip()


def resolve_chain(perm, by_id: dict) -> tuple[str, str]:
    """Follow a permission's parent chain to the scope that actually applies.

    ``Parent`` scope delegates: the rows a visitor reaches are whatever the
    parent permission lets them reach. Two Parent-scoped records on the same
    table, same relationship and same roles can therefore differ completely,
    and the chain is the only thing that says so.
    """
    hops = [perm.scope or "unset"]
    current = by_id.get((perm.parent_id or "").lower())
    seen = {perm.id.lower()}
    while current and current.id.lower() not in seen:
        seen.add(current.id.lower())
        hops.append(current.scope or "unset")
        current = by_id.get((current.parent_id or "").lower())
    return hops[-1], ">".join(hops)


# Tie-breakers, most informative first. Each yields a value per record; the
# first where every record in the group has a distinct, non-empty value wins.
# All are intrinsic to the permission record. Web roles are deliberately absent:
# a role binding is not a property of the grant, role names drift, and a
# permission can carry several — the only role fact that belongs in the name is
# whether it is reachable anonymously, which ANON_MARKER covers.
_DISCRIMINATORS = [
    (lambda r: r.root_scope, "via {}", "the scope its parent chain resolves to"),
    (lambda r: r.relationship, "through {}", "relationship"),
    (lambda r: r.website, "{}", "website"),
]


def _deduplicate(renames: list[Rename], max_name: int = DEFAULT_MAX_NAME) -> None:
    """Two permissions can be identical bar their chain; names cannot.

    Where the template collapses several records onto one name, the whole group
    takes the same tie-breaker so the result reads consistently. Falling all the
    way through to a counter is itself a finding: the records really are
    indistinguishable.
    """
    groups: dict[str, list[Rename]] = {}
    for rename in renames:
        groups.setdefault(rename.proposed.lower(), []).append(rename)

    for group in groups.values():
        if len(group) < 2:
            continue
        for extract, shape, label in _DISCRIMINATORS:
            values = [extract(r) for r in group]
            if all(values) and len(set(values)) == len(values):
                for rename, value in zip(group, values):
                    suffix = " (" + shape.format(value) + ")"
                    rename.proposed = (rename.proposed + suffix)[:max_name].rstrip()
                    rename.reason = f"disambiguated by {label}"
                break
        else:
            for index, rename in enumerate(group, 1):
                rename.proposed = f"{rename.proposed} #{index}"[:max_name].rstrip()
                rename.reason = ("identical table, scope, chain, relationship and "
                                 "privileges — these differ only by role binding, so "
                                 "consider merging them into one permission")


def plan(model, template: str = DEFAULT_TEMPLATE, *,
         only_unclear: bool = False, anon_marker: str = ANON_MARKER,
         max_name: int = DEFAULT_MAX_NAME) -> Plan:
    """Compute proposed names for every table permission in ``model``."""
    validate_template(template)
    result = Plan(template=template,
                  entity_set=model.entity_sets.get("entitypermission", ""),
                  name_field=model.perm_name_field,
                  kind="table permission",
                  anon_marker=anon_marker, max_name=max_name)
    anon_roles = model.role_names(lambda r: r.is_anonymous)
    by_id = {p.id.lower(): p for p in model.permissions if p.id}
    names = {p.id.lower(): p.name for p in model.permissions if p.id}

    for perm in model.permissions:
        root_scope, scope_chain = resolve_chain(perm, by_id)
        parent = names.get((perm.parent_id or "").lower(), "")
        relationship = (perm.contact_relationship or perm.account_relationship
                        or perm.parent_relationship or "")
        website = model.website_name(perm.website_id)
        proposed = build_name(
            template,
            table=perm.table,
            scope=perm.scope,
            scope_chain=scope_chain,
            root_scope=root_scope,
            parent=parent,
            relationship=relationship,
            privileges=perm.privileges(),
            roles=perm.roles,
            website=website,
            current=perm.name,
            max_name=max_name,
        )
        rename = Rename(
            record_id=perm.id, generation=model.generation, table=perm.table,
            scope=perm.scope or "unset", privileges=perm.privileges(),
            roles=list(perm.roles), current=perm.name, proposed=proposed,
            anonymous=any(r in anon_roles for r in perm.roles),
            root_scope=root_scope, scope_chain=scope_chain, parent=parent,
            relationship=relationship, website=website)
        if only_unclear and _is_self_describing(perm):
            rename.proposed = perm.name
            rename.reason = "already names its table and scope"
        result.renames.append(rename)

    _deduplicate(result.renames, max_name)
    _mark_anonymous(result.renames, anon_marker, max_name)
    return result


def _mark_anonymous(renames: list[Rename], marker: str,
                    max_name: int = DEFAULT_MAX_NAME) -> None:
    """Flag public-facing grants, trimming the name rather than the marker."""
    if not marker:
        return
    for rename in renames:
        if not rename.anonymous or marker.lower() in rename.proposed.lower():
            continue
        room = max_name - len(marker) - 1
        rename.proposed = f"{rename.proposed[:room].rstrip()} {marker}"


def _is_self_describing(perm) -> bool:
    """A name already mentioning the table and the scope is left alone."""
    lowered = perm.name.lower()
    table = (perm.table or "").lower()
    scope = (perm.scope or "").lower()
    return bool(table and table in lowered and scope and scope in lowered)


def plan_profiles(model, template: str = DEFAULT_PROFILE_TEMPLATE, *,
                  only_unclear: bool = False, anon_marker: str = ANON_MARKER,
                  max_name: int = DEFAULT_MAX_NAME) -> Plan:
    """Proposed names for every column permission profile in ``model``."""
    validate_template(template, PROFILE_PLACEHOLDERS)
    result = Plan(template=template,
                  entity_set=model.entity_sets.get("columnpermissionprofile", ""),
                  name_field=model.cpp_name_field,
                  kind="column permission profile",
                  anon_marker=anon_marker, max_name=max_name)
    anon_roles = model.role_names(lambda r: r.is_anonymous)

    for profile in model.profiles:
        website = model.website_name(profile.website_id)
        proposed = template.format(
            table=profile.table or "(unknown table)",
            permissions=column_permission_code(profile.all_permissions),
            permissions_long="/".join(profile.all_permissions) or "none",
            columns=len(profile.columns),
            columns_label=("1 column" if len(profile.columns) == 1
                           else f"{len(profile.columns)} columns"),
            columns_flag="+columns" if profile.columns else "",
            roles=", ".join(profile.roles) or "unbound",
            website=website,
            name=profile.name,
        )
        proposed = " ".join(proposed.split())[:max_name].rstrip()
        rename = Rename(
            record_id=profile.id, generation=model.generation,
            table=profile.table, scope="",
            privileges=list(profile.all_permissions),
            roles=list(profile.roles), current=profile.name, proposed=proposed,
            anonymous=any(r in anon_roles for r in profile.roles),
            website=website)
        if only_unclear and profile.table and profile.table.lower() in profile.name.lower():
            rename.proposed = profile.name
            rename.reason = "already names its table"
        result.renames.append(rename)

    _deduplicate(result.renames, max_name)
    _mark_anonymous(result.renames, anon_marker, max_name)
    return result


def apply(client, plan_: Plan, name_field: str = "", *,
          limit: int | None = None) -> list[str]:
    """Write the proposed names back. Returns the errors encountered."""
    field_name = name_field or plan_.name_field
    if not plan_.entity_set or not field_name:
        raise NamingError(f"Plan for {plan_.kind} is missing its entity set or "
                          "name column; refusing to write.")
    errors: list[str] = []
    for rename in plan_.changes[:limit]:
        if not rename.record_id:
            errors.append(f"{rename.current}: no record id, skipped")
            continue
        try:
            client.patch(plan_.entity_set, rename.record_id,
                         {field_name: rename.proposed})
        except Exception as exc:  # surfaced per record so one failure is not fatal
            errors.append(f"{rename.current} -> {rename.proposed}: {exc}")
    return errors
