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

# adx_entityname is a 100-character name field.
MAX_NAME = 100

DEFAULT_TEMPLATE = "{table} [{privileges}] ({scope_chain})"

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
    "table", "scope", "scope_chain", "root_scope", "parent",
    "privileges", "privileges_compact", "privileges_long",
    "roles", "website", "name",
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
            "parent": self.parent,
            "changed": self.changed, "reason": self.reason,
        }


@dataclass
class Plan:
    template: str
    renames: list[Rename] = field(default_factory=list)
    entity_set: str = ""
    anon_marker: str = ANON_MARKER

    @property
    def changes(self) -> list[Rename]:
        return [r for r in self.renames if r.changed]

    def to_dict(self) -> dict[str, Any]:
        return {"template": self.template, "entity_set": self.entity_set,
                "anon_marker": self.anon_marker,
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


def validate_template(template: str) -> None:
    unknown = set(re.findall(r"\{(\w+)\}", template)) - PLACEHOLDERS
    if unknown:
        raise NamingError(
            f"Unknown placeholder(s) {', '.join(sorted(unknown))}. "
            f"Available: {', '.join(sorted(PLACEHOLDERS))}.")


def build_name(template: str, *, table: str, scope: str, privileges: list[str],
               roles: list[str], website: str, current: str,
               scope_chain: str = "", root_scope: str = "", parent: str = "") -> str:
    name = template.format(
        table=table or "(unknown table)",
        scope=scope or "unset",
        scope_chain=scope_chain or scope or "unset",
        root_scope=root_scope or scope or "unset",
        parent=parent or "none",
        privileges=privilege_code(privileges),
        privileges_compact=privilege_compact(privileges),
        privileges_long="/".join(privileges) or "none",
        roles=", ".join(roles) or "unbound",
        website=website,
        name=current,
    )
    name = " ".join(name.split())
    return name[:MAX_NAME].rstrip()


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
_DISCRIMINATORS = [
    (lambda r: ", ".join(r.roles), "{}", "web role"),
    (lambda r: r.root_scope, "via {}", "the scope its parent chain resolves to"),
    (lambda r: r.parent, "under {}", "parent table permission"),
]


def _deduplicate(renames: list[Rename]) -> None:
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
                    rename.proposed = (rename.proposed + suffix)[:MAX_NAME].rstrip()
                    rename.reason = f"disambiguated by {label}"
                break
        else:
            for index, rename in enumerate(group, 1):
                rename.proposed = f"{rename.proposed} #{index}"[:MAX_NAME].rstrip()
                rename.reason = ("no distinguishing table, scope, chain, privileges "
                                 "or roles — check whether these records are duplicates")


def plan(model, template: str = DEFAULT_TEMPLATE, *,
         only_unclear: bool = False, anon_marker: str = ANON_MARKER) -> Plan:
    """Compute proposed names for every table permission in ``model``."""
    validate_template(template)
    result = Plan(template=template,
                  entity_set=model.entity_sets.get("entitypermission", ""),
                  anon_marker=anon_marker)
    anon_roles = model.role_names(lambda r: r.is_anonymous)
    by_id = {p.id.lower(): p for p in model.permissions if p.id}
    names = {p.id.lower(): p.name for p in model.permissions if p.id}

    for perm in model.permissions:
        root_scope, scope_chain = resolve_chain(perm, by_id)
        parent = names.get((perm.parent_id or "").lower(), "")
        proposed = build_name(
            template,
            table=perm.table,
            scope=perm.scope,
            scope_chain=scope_chain,
            root_scope=root_scope,
            parent=parent,
            privileges=perm.privileges(),
            roles=perm.roles,
            website=model.website_name(perm.website_id),
            current=perm.name,
        )
        rename = Rename(
            record_id=perm.id, generation=model.generation, table=perm.table,
            scope=perm.scope or "unset", privileges=perm.privileges(),
            roles=list(perm.roles), current=perm.name, proposed=proposed,
            anonymous=any(r in anon_roles for r in perm.roles),
            root_scope=root_scope, scope_chain=scope_chain, parent=parent)
        if only_unclear and _is_self_describing(perm):
            rename.proposed = perm.name
            rename.reason = "already names its table and scope"
        result.renames.append(rename)

    _deduplicate(result.renames)
    _mark_anonymous(result.renames, anon_marker)
    return result


def _mark_anonymous(renames: list[Rename], marker: str) -> None:
    """Flag public-facing grants, trimming the name rather than the marker."""
    if not marker:
        return
    for rename in renames:
        if not rename.anonymous or marker.lower() in rename.proposed.lower():
            continue
        room = MAX_NAME - len(marker) - 1
        rename.proposed = f"{rename.proposed[:room].rstrip()} {marker}"


def _is_self_describing(perm) -> bool:
    """A name already mentioning the table and the scope is left alone."""
    lowered = perm.name.lower()
    table = (perm.table or "").lower()
    scope = (perm.scope or "").lower()
    return bool(table and table in lowered and scope and scope in lowered)


def apply(client, plan_: Plan, name_field: str, *, limit: int | None = None) -> list[str]:
    """Write the proposed names back. Returns the errors encountered."""
    if not plan_.entity_set:
        raise NamingError("No table permission entity set on the plan.")
    errors: list[str] = []
    for rename in plan_.changes[:limit]:
        if not rename.record_id:
            errors.append(f"{rename.current}: no record id, skipped")
            continue
        try:
            client.patch(plan_.entity_set, rename.record_id,
                         {name_field: rename.proposed})
        except Exception as exc:  # surfaced per record so one failure is not fatal
            errors.append(f"{rename.current} -> {rename.proposed}: {exc}")
    return errors
