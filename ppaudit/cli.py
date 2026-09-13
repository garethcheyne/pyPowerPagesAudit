"""Command-line interface for the Power Pages / Dataverse exposure audit.

Subcommands
-----------
    scan   Anonymous, unauthenticated outside-in scan of a Power Pages site.
    audit  Authenticated inside-out Dataverse permission audit.
    full   Both, then correlate external leaks to their root-cause permission.

Examples
--------
    ppaudit scan  --url contoso.powerappsportals.com --html report.html
    ppaudit audit --org-url https://contoso.crm.dynamics.com --markdown audit.md
    ppaudit full  --url contoso.powerappsportals.com \
                  --org-url https://contoso.crm.dynamics.com \
                  --markdown report.md --json report.json

``--markdown`` is the reviewable output: it lays out web roles, table
permissions, column permission profiles, Web API site settings, OData feeds and
page access rules alongside the findings, so a reviewer can check the
configuration against intent.

Authenticated calls use Azure AD client credentials. Provide them via
TENANT_ID / CLIENT_ID / CLIENT_SECRET environment variables (preferred) or the
--tenant-id / --client-id / --client-secret flags. The app registration must be
an Application User in the target environment with read access to the Power
Pages configuration tables.

Rather than passing URLs, list the environments in ``instances.yaml`` next to a
``.env`` holding the secrets, and run ``ppaudit full`` with no arguments: every
instance is audited in turn and each gets its own report file.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .anonscan import AnonScanner
from .audit import DataverseAudit
from .config import Config, ConfigError, Instance, credentials_summary, load_config, load_dotenv
from .dataverse import DataverseClient, DataverseError
from . import naming
from .report import Report, Severity


def _out_path(path: str, suffix: str) -> str:
    """Insert an instance slug before the extension so runs do not overwrite."""
    p = Path(path)
    return str(p.with_name(f"{p.stem}-{suffix}{p.suffix}"))


def _emit(report: Report, args, suffix: str = "") -> None:
    print(report.to_console(color=not args.no_color))
    for attr, render, label in (
        ("json", report.to_json, "JSON"),
        ("markdown", report.to_markdown, "Markdown"),
        ("html", report.to_html, "HTML"),
    ):
        path = getattr(args, attr, None)
        if not path:
            continue
        if suffix:
            path = _out_path(path, suffix)
        parent = Path(path).parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render())
        print(f"{label} written to {path}")


def _parse_headers(values: list[str] | None) -> dict[str, str]:
    headers = {}
    for item in values or []:
        if ":" in item:
            k, _, v = item.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def _run_scan(args, report: Report, url: str) -> None:
    scanner = AnonScanner(
        url,
        threads=args.threads,
        rate=args.rate,
        timeout=args.timeout,
        extra_headers=_parse_headers(args.header),
        probe_common=not args.no_common,
        verbose=args.verbose,
    )
    scanner.scan(report)


def _run_audit(args, report: Report, org_url: str, website: str = "",
               portal_url: str = "") -> None:
    client = DataverseClient(
        org_url,
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
    )
    try:
        who = client.whoami()
        report.context["whoami"] = who.get("UserId", "")
    except DataverseError as exc:
        print(f"warning: WhoAmI failed: {exc}", file=sys.stderr)
    DataverseAudit(client, website=website or args.website,
                   portal_url=portal_url).run(report)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ppaudit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--instances", metavar="PATH", nargs="?", const="",
                        help="audit every environment in an instances.yaml "
                             "(default: ./instances.yaml)")
        sp.add_argument("--env", metavar="PATH", help="path to the .env holding the secrets")
        sp.add_argument("--json", metavar="PATH", help="write findings as JSON")
        sp.add_argument("--markdown", "--md", metavar="PATH", dest="markdown",
                        help="write a full Markdown review document (configuration "
                             "inventory + findings)")
        sp.add_argument("--html", metavar="PATH", help="write findings as an HTML report")
        sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
        sp.add_argument("--verbose", action="store_true")

    def anon_opts(sp):
        sp.add_argument("--url", help="Power Pages site URL (omit when using --instances)")
        sp.add_argument("--threads", type=int, default=8)
        sp.add_argument("--rate", type=float, default=0.0,
                        help="min seconds between requests (politeness)")
        sp.add_argument("--timeout", type=float, default=10.0)
        sp.add_argument("--header", action="append",
                        help="extra request header 'K: V' (e.g. a session cookie "
                             "to scan as an authenticated portal user); repeatable")
        sp.add_argument("--no-common", action="store_true",
                        help="only probe tables found in $metadata, skip the wordlist")

    def dv_opts(sp):
        sp.add_argument("--org-url",
                        help="Dataverse org URL, e.g. https://contoso.crm.dynamics.com "
                             "(omit when using --instances)")
        sp.add_argument("--tenant-id", help="Azure AD tenant id (or TENANT_ID env)")
        sp.add_argument("--client-id", help="app registration client id (or CLIENT_ID env)")
        sp.add_argument("--client-secret", help="client secret (or CLIENT_SECRET env)")
        sp.add_argument("--website", metavar="NAME",
                        help="restrict the audit to websites whose name contains NAME "
                             "(useful when one environment hosts several sites)")

    sp_scan = sub.add_parser("scan", help="anonymous outside-in scan")
    anon_opts(sp_scan); common(sp_scan)

    sp_audit = sub.add_parser("audit", help="authenticated Dataverse permission audit")
    dv_opts(sp_audit); common(sp_audit)

    sp_full = sub.add_parser("full", help="scan + audit + correlation")
    anon_opts(sp_full); dv_opts(sp_full); common(sp_full)

    sp_naming = sub.add_parser(
        "naming",
        help="propose self-describing names for table permission records",
        description=(
            "Rebuilds every adx_entityname / mspp_entityname from the grant it "
            "describes, so a reviewer can read the security model from the record "
            "list instead of opening each one.\n\n"
            "Dry run by default; --apply writes the names to Dataverse."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    dv_opts(sp_naming)
    sp_naming.add_argument(
        "--format", default=naming.DEFAULT_TEMPLATE, metavar="TEMPLATE",
        help="naming template. Placeholders: "
             "{table} {scope} {privileges} {privileges_long} {roles} {website} "
             f"{{name}}. Default: '{naming.DEFAULT_TEMPLATE}'")
    sp_naming.add_argument(
        "--only-unclear", action="store_true",
        help="leave names that already mention their table and scope")
    sp_naming.add_argument(
        "--anon-marker", default=naming.ANON_MARKER, metavar="TEXT",
        help="suffix for permissions bound to an Anonymous Users role "
             f"(default: '{naming.ANON_MARKER}'; pass '' to disable)")
    sp_naming.add_argument(
        "--apply", action="store_true",
        help="write the proposed names to Dataverse (default is a dry run)")
    sp_naming.add_argument("--instances", metavar="PATH", nargs="?", const="",
                           help="use an instances.yaml (default: ./instances.yaml)")
    sp_naming.add_argument("--env", metavar="PATH", help="path to the .env")
    sp_naming.add_argument("--no-color", action="store_true")
    sp_naming.add_argument("--verbose", action="store_true")
    return p


def _run_naming(args, report: Report, org_url: str, website: str = "") -> int:
    """Propose (and optionally write) self-describing table permission names."""
    from .model import ConfigLoader
    from . import naming

    try:
        naming.validate_template(args.format)
    except naming.NamingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    client = DataverseClient(
        org_url,
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
    )
    plans = []
    for gen, cfg in client.detect_schemas():
        model = ConfigLoader(client, gen, cfg).load()
        if not model.in_use:
            continue
        name_filter = (website or args.website or "").strip().lower()
        if name_filter:
            model = _filter_model_to_website(model, name_filter)
        plans.append((model, naming.plan(model, args.format,
                                         only_unclear=args.only_unclear,
                                         anon_marker=args.anon_marker)))

    if not plans:
        print("No configuration generation in use; nothing to rename.", file=sys.stderr)
        return 0

    total_changes = 0
    for model, plan in plans:
        changes = plan.changes
        total_changes += len(changes)
        anon = sum(1 for r in plan.renames if r.anonymous)
        print(f"\n{model.label} ({model.generation}_*) — "
              f"{len(changes)} of {len(plan.renames)} would change; "
              f"{anon} bound to an anonymous role")
        print(f"template: {plan.template}\n")
        if not changes:
            continue
        width = min(52, max((len(r.current) for r in changes), default=10))
        for rename in sorted(changes, key=lambda r: (not r.anonymous,
                                                     r.table.lower(), r.proposed)):
            note = f"   [{rename.reason}]" if rename.reason else ""
            print(f"  {rename.current[:width]:<{width}}  ->  {rename.proposed}{note}")

    report.context["naming_plans"] = [p.to_dict() for _, p in plans]

    if not args.apply:
        print(f"\nDry run. {total_changes} record(s) would be renamed. "
              f"Re-run with --apply to write these names to Dataverse.")
        return 0

    for model, plan in plans:
        if not plan.changes:
            continue
        if not model.perm_name_field:
            print(f"{model.label}: could not determine the name column; skipped",
                  file=sys.stderr)
            continue
        errors = naming.apply(client, plan, model.perm_name_field)
        done = len(plan.changes) - len(errors)
        print(f"\n{model.label}: renamed {done} record(s).")
        for err in errors:
            print(f"  failed: {err}", file=sys.stderr)
    return 0


def _filter_model_to_website(model, needle: str):
    from .audit import _filter_to_website

    return _filter_to_website(model, needle)


def _run_one(args, inst: Instance, suffix: str = "") -> Report:
    """Run the requested stages against one environment and emit its reports."""
    target = inst.portal_url or inst.dataverse_url
    report = Report(target=target)
    report.context["instance"] = inst.name
    if inst.dataverse_url:
        report.context["dataverse_url"] = inst.dataverse_url
    if inst.portal_url:
        report.context["portal_url"] = inst.portal_url

    wants_scan = args.command in ("scan", "full")
    wants_audit = args.command in ("audit", "full")

    if args.command == "naming":
        if inst.dataverse_url:
            _run_naming(args, report, inst.dataverse_url, inst.website)
        else:
            print(f"warning: {inst.name}: no dataverse_url", file=sys.stderr)
        return report

    if wants_scan and inst.portal_url:
        _run_scan(args, report, inst.portal_url)   # populates anon_exposed_tables first
    elif wants_scan:
        print(f"warning: {inst.name}: no portal_url, skipping anonymous scan", file=sys.stderr)

    if wants_audit and inst.dataverse_url:
        try:
            _run_audit(args, report, inst.dataverse_url, inst.website,
                       inst.portal_url)  # correlation uses the scan
        except DataverseError as exc:
            print(f"error: {inst.name}: {exc}", file=sys.stderr)
    elif wants_audit:
        print(f"warning: {inst.name}: no dataverse_url, skipping Dataverse audit", file=sys.stderr)

    _emit(report, args, suffix)
    return report

def _resolve_targets(args) -> tuple[list[Instance], Config | None]:
    """Decide what to audit: explicit URLs, or every instance in the YAML."""
    if args.instances is None and (getattr(args, "url", None) or getattr(args, "org_url", None)):
        load_dotenv(args.env)
        return [Instance(name="target",
                         dataverse_url=(getattr(args, "org_url", "") or "").rstrip("/"),
                         portal_url=(getattr(args, "url", "") or "").rstrip("/"),
                         website=getattr(args, "website", "") or "")], None

    cfg = load_config(args.instances or None, env_path=args.env)
    args.tenant_id = args.tenant_id or cfg.tenant_id
    args.client_id = args.client_id or cfg.client_id
    args.client_secret = args.client_secret or cfg.client_secret
    for key, value in (("TENANT_ID", cfg.tenant_id), ("CLIENT_ID", cfg.client_id),
                       ("CLIENT_SECRET", cfg.client_secret)):
        if value:
            os.environ.setdefault(key, value)
    return cfg.instances, cfg


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")  # cp1252 mangles the report glyphs
    args = build_parser().parse_args(argv)
    for attr in ("tenant_id", "client_id", "client_secret", "website"):
        if not hasattr(args, attr):
            setattr(args, attr, "")

    try:
        instances, cfg = _resolve_targets(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if cfg:
        print(f"config: {cfg.source} ({len(instances)} instance(s)); "
              f"credentials {credentials_summary(cfg)}\n", file=sys.stderr)

    reports: list[Report] = []
    try:
        for inst in instances:
            if len(instances) > 1:
                print(f"\n=== {inst.name} ===", file=sys.stderr)
            reports.append(_run_one(args, inst, inst.slug if len(instances) > 1 else ""))
    except DataverseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    # Non-zero exit if anything high or above, so CI can gate on it.
    worst = max((f.severity for r in reports for f in r.findings), default=Severity.INFO)
    return 1 if worst >= Severity.HIGH else 0


if __name__ == "__main__":
    raise SystemExit(main())
