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

Run from a terminal, anything left unsaid is asked for: ``ppaudit`` alone asks
what to do, a file listing several sites asks which one, and a run with no
report flags asks what to save. The equivalent full command is printed so it
can be reused. ``--instance NAME`` picks a site up front; ``--no-input`` (or any
non-terminal run, such as CI) never prompts.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from .anonscan import AnonScanner
from .audit import DataverseAudit
from .config import Config, ConfigError, Instance, credentials_summary, load_config, load_dotenv
from .dataverse import DataverseClient, DataverseError
from . import naming, prompts
from .report import Report, Severity


def _out_path(path: str, slug: str, stamp: str) -> str:
    """Give each instance its own folder and each run its own filename.

    ``reports/audit.html`` becomes
    ``reports/contoso-production/audit-20260916-142530.html``. Reports are
    evidence of what a site looked like at a moment, so a second run must not
    quietly replace the first — and a scan of one site must never land on top of
    an audit of another.
    """
    p = Path(path)
    parent = p.parent / slug if slug else p.parent
    stem = f"{p.stem}-{stamp}" if stamp else p.stem
    return str(parent / f"{stem}{p.suffix}")


def _run_stamp() -> str:
    """One timestamp per run, so an instance's reports sort and group together."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _host_of(url: str) -> str:
    """Name a target given only as a URL after its host.

    The name becomes the report folder, so ``contoso.crm.dynamics.com`` beats a
    generic ``target`` that every ad-hoc run would pile into.
    """
    host = url.split("//", 1)[-1].split("/", 1)[0]
    return host or "target"


def _emit(report: Report, args, slug: str = "", stamp: str = "") -> None:
    print(report.to_console(color=not args.no_color))
    for attr, render, label in (
        ("json", report.to_json, "JSON"),
        ("markdown", report.to_markdown, "Markdown"),
        ("html", report.to_html, "HTML"),
    ):
        path = getattr(args, attr, None)
        if not path:
            continue
        path = _out_path(path, slug, stamp)
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
    report.context["entity_sets_map"] = client.entity_set_names()
    DataverseAudit(client, website=website or args.website,
                   portal_url=portal_url,
                   check_versions=not getattr(args, "no_version_check", False)).run(report)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ppaudit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # Not required: with no command, a terminal user is asked what to run.
    sub = p.add_subparsers(dest="command")

    def selection(sp):
        sp.add_argument("--instance", metavar="NAME", action="append",
                        help="only the instance with this name (or slug) from "
                             "instances.yaml; repeatable. Without it, a terminal "
                             "run with several instances asks which to use")
        sp.add_argument("--no-input", action="store_true",
                        help="never prompt; use flags and defaults only")

    def common(sp):
        sp.add_argument("--instances", metavar="PATH", nargs="?", const="",
                        help="audit every environment in an instances.yaml "
                             "(default: ./instances.yaml)")
        selection(sp)
        sp.add_argument("--env", metavar="PATH", help="path to the .env holding the secrets")
        sp.add_argument("--json", metavar="PATH", help="write findings as JSON")
        sp.add_argument("--markdown", "--md", metavar="PATH", dest="markdown",
                        help="write a full Markdown review document (configuration "
                             "inventory + findings)")
        sp.add_argument("--html", metavar="PATH", help="write findings as an HTML report")
        sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
        sp.add_argument("--no-probe", action="store_true",
                        help="skip the anonymous reachability probe of published URLs "
                             "(no live requests to the portal's pages)")
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
        sp.add_argument("--no-version-check", action="store_true",
                        help="skip fetching Microsoft's published release list "
                             "(keeps the audit entirely offline)")

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
        "--target", choices=("permissions", "profiles", "all"), default="all",
        help="which records to rename (default: all)")
    sp_naming.add_argument(
        "--format", default=naming.DEFAULT_TEMPLATE, metavar="TEMPLATE",
        help="table permission template. Placeholders: "
             "{table} {scope} {scope_chain} {root_scope} {parent} {relationship} "
             "{privileges} {privileges_compact} {privileges_long} {roles} "
             f"{{website}} {{name}}. Default: '{naming.DEFAULT_TEMPLATE}'")
    sp_naming.add_argument(
        "--profile-format", default=naming.DEFAULT_PROFILE_TEMPLATE, metavar="TEMPLATE",
        help="column permission profile template. Placeholders: "
             "{table} {permissions} {permissions_long} {columns} {roles} "
             f"{{website}} {{name}}. Default: '{naming.DEFAULT_PROFILE_TEMPLATE}'")
    sp_naming.add_argument(
        "--only-unclear", action="store_true",
        help="leave names that already mention their table and scope")
    sp_naming.add_argument(
        "--anon-marker", default=naming.ANON_MARKER, metavar="TEXT",
        help="suffix for permissions bound to an Anonymous Users role "
             f"(default: '{naming.ANON_MARKER}'; pass '' to disable)")
    sp_naming.add_argument(
        "--max-name", type=int, metavar="N",
        help="override the name length limit (default: read from the "
             "environment's column metadata)")
    sp_naming.add_argument(
        "--apply", action="store_true",
        help="write the proposed names to Dataverse (default is a dry run)")
    sp_naming.add_argument("--instances", metavar="PATH", nargs="?", const="",
                           help="use an instances.yaml (default: ./instances.yaml)")
    sp_naming.add_argument("--env", metavar="PATH", help="path to the .env")
    selection(sp_naming)
    sp_naming.add_argument("--no-color", action="store_true")
    sp_naming.add_argument("--verbose", action="store_true")
    return p


def _run_naming(args, report: Report, org_url: str, website: str = "") -> int:
    """Propose (and optionally write) self-describing table permission names."""
    from .model import ConfigLoader
    from . import naming

    try:
        naming.validate_template(args.format)
        naming.validate_template(args.profile_format, naming.PROFILE_PLACEHOLDERS)
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

        if args.target in ("permissions", "all"):
            limit = args.max_name or client.string_max_length(
                f"{gen}_entitypermission",
                model.perm_name_field) or naming.DEFAULT_MAX_NAME
            plans.append((model, naming.plan(
                model, args.format, only_unclear=args.only_unclear,
                anon_marker=args.anon_marker, max_name=limit)))

        if args.target in ("profiles", "all"):
            limit = args.max_name or client.string_max_length(
                f"{gen}_columnpermissionprofile",
                model.cpp_name_field) or naming.DEFAULT_MAX_NAME
            plans.append((model, naming.plan_profiles(
                model, args.profile_format, only_unclear=args.only_unclear,
                anon_marker=args.anon_marker, max_name=limit)))

    if not plans:
        print("No configuration generation in use; nothing to rename.", file=sys.stderr)
        return 0

    total_changes = 0
    for model, plan in plans:
        changes = plan.changes
        total_changes += len(changes)
        anon = sum(1 for r in plan.renames if r.anonymous)
        print(f"\n{model.label} ({model.generation}_*) — {plan.kind}s: "
              f"{len(changes)} of {len(plan.renames)} would change; "
              f"{anon} bound to an anonymous role")
        print(f"template: {plan.template}")
        print(f"{plan.name_field or '(unknown column)'} accepts {plan.max_name} "
              f"characters; longest proposed name is {plan.longest}\n")
        if not changes:
            continue
        width = min(52, max((len(r.current) for r in changes), default=10))
        notes: list[str] = []
        for rename in sorted(changes, key=lambda r: (not r.anonymous,
                                                     r.table.lower(), r.proposed)):
            print(f"  {rename.current[:width]:<{width}}  ->  {rename.proposed}")
            if rename.reason:
                notes.append(f"  {rename.proposed}\n      note: {rename.reason}")
        if notes:
            print("\n  Notes (not part of the name):")
            for note in notes:
                print(note)

    report.context["naming_plans"] = [p.to_dict() for _, p in plans]

    if not args.apply:
        print(f"\nDry run. {total_changes} record(s) would be renamed. "
              f"Re-run with --apply to write these names to Dataverse.")
        return 0

    for model, plan in plans:
        if not plan.changes:
            continue
        if not plan.name_field:
            print(f"{model.label} {plan.kind}s: could not determine the name "
                  "column; skipped", file=sys.stderr)
            continue
        errors = naming.apply(client, plan)
        done = len(plan.changes) - len(errors)
        print(f"\n{model.label} {plan.kind}s: renamed {done} record(s).")
        for err in errors:
            print(f"  failed: {err}", file=sys.stderr)
    return 0


def _filter_model_to_website(model, needle: str):
    from .audit import _filter_to_website

    return _filter_to_website(model, needle)


def _run_one(args, inst: Instance, stamp: str = "") -> Report:
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
            # A bad template or a failed write must not exit 0: the caller asked
            # for records to be renamed and they were not.
            report.context["naming_exit"] = _run_naming(
                args, report, inst.dataverse_url, inst.website)
        else:
            print(f"warning: {inst.name}: no dataverse_url", file=sys.stderr)
            report.context["naming_exit"] = 2
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

    if inst.portal_url and not getattr(args, "no_probe", False):
        _probe_published(report, inst.portal_url)

    _emit(report, args, inst.slug, stamp)
    return report


def _probe_published(report: Report, portal_url: str) -> None:
    """Ask the live site, anonymously, which published URLs a visitor can reach."""
    from . import pageprobe

    base = portal_url.rstrip("/")
    urls: list[str] = []
    for model in getattr(report, "models", []) or []:
        if not getattr(model, "in_use", True):
            continue
        urls += [r.url for r in model.published_pages(base)]
        urls += [r.url for r in model.published_files(base)]
    if urls:
        print(f"probing {len(set(urls))} published URL(s) anonymously…", file=sys.stderr)
        results = pageprobe.probe_urls(urls)
        report.context["url_probes"] = {
            url: {"status": r.status, "verdict": r.verdict, "final_path": r.final_path}
            for url, r in results.items()}

    _probe_endpoints(report, base)


def _probe_endpoints(report: Report, base: str) -> None:
    """Anonymously hit each data endpoint and read its body to say what it returns.

    Uses the environment's real entity-set names so the ``_api``/``_odata`` paths
    are the ones a caller would actually use, and records the OData surface being
    switched off rather than presenting its dead URLs as reachable.
    """
    from . import pageprobe

    es_map = report.context.get("entity_sets_map") or {}
    tables: dict[str, str] = {}   # entity-set name -> display (logical) name
    for model in getattr(report, "models", []) or []:
        if not getattr(model, "in_use", True):
            continue
        for w in getattr(model, "webapi", []):
            if getattr(w, "enabled", False):
                tables[es_map.get(w.entity, w.entity)] = w.entity
    for t in report.context.get("anon_exposed_tables") or []:
        tables.setdefault(t, t)

    candidates: list[tuple[str, str, str]] = [("metadata", "OData schema",
                                               f"{base}/_odata/$metadata")]
    for es, logical in sorted(tables.items()):
        candidates.append((logical, "Web API", f"{base}/_api/{es}"))
        candidates.append((logical, "OData feed", f"{base}/_odata/{es}"))

    print(f"probing {len(candidates)} data endpoint(s) anonymously…", file=sys.stderr)
    probed = pageprobe.probe_endpoints([u for _, _, u in candidates])
    report.context["endpoint_probes"] = [
        {"table": table, "surface": surface, "url": url,
         "status": (r := probed[url]).status, "verdict": r.verdict, "note": r.note}
        for table, surface, url in candidates if url in probed]

def _resolve_targets(args) -> tuple[list[Instance], Config | None]:
    """Decide what to audit: explicit URLs, or instances from the YAML."""
    if args.instances is None and (getattr(args, "url", None) or getattr(args, "org_url", None)):
        load_dotenv(args.env)
        portal = (getattr(args, "url", "") or "").rstrip("/")
        dataverse = (getattr(args, "org_url", "") or "").rstrip("/")
        return [Instance(name=_host_of(portal or dataverse),
                         dataverse_url=dataverse, portal_url=portal,
                         website=getattr(args, "website", "") or "")], None

    try:
        cfg = load_config(args.instances or None, env_path=args.env)
    except ConfigError:
        # Only a missing default file is recoverable by asking; a named file
        # that is absent or malformed is an error the user needs to see.
        if args.instances is not None or not prompts.interactive(args):
            raise
        return [_prompt_target(args)], None

    args.tenant_id = args.tenant_id or cfg.tenant_id
    args.client_id = args.client_id or cfg.client_id
    args.client_secret = args.client_secret or cfg.client_secret
    for key, value in (("TENANT_ID", cfg.tenant_id), ("CLIENT_ID", cfg.client_id),
                       ("CLIENT_SECRET", cfg.client_secret)):
        if value:
            os.environ.setdefault(key, value)
    print(f"config: {cfg.source} ({len(cfg.instances)} instance(s)); "
          f"credentials {credentials_summary(cfg)}", file=sys.stderr)
    cfg.instances = _select_instances(args, cfg.instances)
    return cfg.instances, cfg


def _select_instances(args, instances: list[Instance]) -> list[Instance]:
    """Narrow the configured instances to the ones this run should touch.

    ``--instance`` wins. Otherwise a terminal user with several sites is asked,
    with no default: Enter must not quietly point a scan at every environment.
    Non-interactive runs keep auditing all of them.
    """
    wanted = [w.strip().lower() for w in (getattr(args, "instance", None) or []) if w.strip()]
    if wanted:
        def matches(inst: Instance, name: str) -> bool:
            return name in (inst.name.lower(), inst.slug)

        unknown = [w for w in wanted if not any(matches(i, w) for i in instances)]
        if unknown:
            available = ", ".join(f"'{i.name}'" for i in instances)
            raise ConfigError(f"no instance named {', '.join(unknown)}. "
                              f"Available: {available}")
        return [i for i in instances if any(matches(i, w) for w in wanted)]

    if len(instances) < 2 or not prompts.interactive(args):
        return instances

    needs_portal = args.command == "scan"
    needs_dataverse = args.command in ("audit", "naming")
    options = []
    for inst in instances:
        hint = inst.portal_url or inst.dataverse_url
        if needs_portal and not inst.portal_url:
            hint = "no portal_url — nothing to scan"
        elif needs_dataverse and not inst.dataverse_url:
            hint = "no dataverse_url — nothing to audit"
        options.append((inst.name, hint))
    options.append(("All sites", f"each of the {len(instances)} in turn"))

    index = prompts.choose("Which site?", options)
    if index == len(instances):
        return instances
    picked = instances[index]
    args.prompted += ["--instance", picked.name]
    return [picked]


def _prompt_target(args) -> Instance:
    """No instances.yaml: ask for the URLs this command needs."""
    print("\nNo instances.yaml in this folder. Enter the site to use "
          "(or Ctrl+C, then pass --instances PATH).")
    portal = dataverse = ""
    if args.command in ("scan", "full"):
        portal = prompts.text("Portal URL", "https://contoso.powerappsportals.com")
        args.url = portal
        args.prompted += ["--url", portal]
    if args.command in ("audit", "full", "naming"):
        dataverse = prompts.text("Dataverse URL", "https://contoso.crm.dynamics.com")
        args.org_url = dataverse
        args.prompted += ["--org-url", dataverse]
    load_dotenv(args.env)
    return Instance(name="target", dataverse_url=dataverse.rstrip("/"),
                    portal_url=portal.rstrip("/"), website=args.website or "")


def _prompt_outputs(args) -> None:
    """Ask what to save when no report flag was given."""
    if args.command == "naming" or not prompts.interactive(args):
        return
    if any(getattr(args, attr, None) for attr in ("json", "markdown", "html")):
        return
    index = prompts.choose("Save a report?", [
        ("HTML report", "reports/audit.html — open it in a browser"),
        ("HTML, Markdown and JSON", "reports/audit.html, .md and .json"),
        ("Console only", "print the findings, save nothing"),
    ], default=0)
    if index in (0, 1):
        args.html = "reports/audit.html"
        args.prompted += ["--html", args.html]
    if index == 1:
        args.markdown, args.json = "reports/audit.md", "reports/audit.json"
        args.prompted += ["--markdown", args.markdown, "--json", args.json]


_ACTIONS = [
    ("full", "Scan and audit", "recommended: outside-in scan, Dataverse audit, "
                               "and each leak tied to its cause"),
    ("scan", "Anonymous scan only", "probe the portal from outside; no credentials"),
    ("audit", "Dataverse audit only", "read the permission model; needs the app "
                                      "registration"),
    ("naming", "Tidy permission names", "propose self-describing record names"),
]


def _wizard() -> list[str]:
    """Ask what to run when no command was given; returns the argv to parse."""
    print("ppaudit — Power Pages exposure audit")
    index = prompts.choose("What do you want to do?",
                           [(label, hint) for _, label, hint in _ACTIONS], default=0)
    argv = [_ACTIONS[index][0]]
    if argv[0] == "naming":
        mode = prompts.choose("Preview or write?", [
            ("Preview the proposed names", "dry run — nothing is written"),
            ("Write the names to Dataverse", "updates the name field on each record"),
        ], default=0)
        if mode == 1:
            if prompts.confirm("This changes records in Dataverse. Continue?"):
                argv.append("--apply")
            else:
                print("Staying with a dry run.")
    return argv


def _command_line(parts: list[str]) -> str:
    quoted = [f'"{p}"' if (" " in p or not p) else p for p in parts]
    return "python -m ppaudit " + " ".join(quoted)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")  # cp1252 mangles the report glyphs
    parser = build_parser()
    given = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(given)

    try:
        if args.command is None:
            if not prompts.interactive():
                parser.print_help(sys.stderr)
                return 2
            given = _wizard()
            args = parser.parse_args(given)
        for attr in ("tenant_id", "client_id", "client_secret", "website"):
            if not hasattr(args, attr):
                setattr(args, attr, "")
        args.prompted = []
        instances, cfg = _resolve_targets(args)
        _prompt_outputs(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (prompts.Aborted, KeyboardInterrupt):
        print("\ncancelled", file=sys.stderr)
        return 130

    if args.prompted or given != list(sys.argv[1:] if argv is None else argv):
        print(f"\nRunning: {_command_line(given + args.prompted)}", file=sys.stderr)
    print(file=sys.stderr)

    reports: list[Report] = []
    stamp = _run_stamp()
    try:
        for inst in instances:
            if len(instances) > 1:
                print(f"\n=== {inst.name} ===", file=sys.stderr)
            reports.append(_run_one(args, inst, stamp))
    except DataverseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    failed = max((r.context.get("naming_exit", 0) for r in reports), default=0)
    if failed:
        return failed

    # Non-zero exit if anything high or above, so CI can gate on it.
    worst = max((f.severity for r in reports for f in r.findings), default=Severity.INFO)
    return 1 if worst >= Severity.HIGH else 0


if __name__ == "__main__":
    raise SystemExit(main())
