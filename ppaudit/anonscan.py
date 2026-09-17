"""Anonymous, outside-in Power Pages exposure scanner.

This is the power-pwn Power Pages technique, reimplemented and extended:

* discovers exposed tables from ``/_odata/$metadata`` (schema disclosure is a
  finding in itself), **and** probes a wordlist of high-value tables directly,
  so a locked-down metadata document does not hide a leaking entity set;
* checks both the ``/_odata`` feed and the ``/_api`` Web API surface;
* reports how many rows are reachable (``$count``), not just yes/no;
* on a table-permission error falls back to per-column probing to find
  partial column-level leaks;
* runs probes concurrently, with optional rate limiting for politeness. A probe
  that never gets an answer is recorded as such rather than read as a pass:
  where nothing answers at all, the scan says the target was untested.

It authenticates nothing by default (the anonymous attacker's view). An
optional cookie/bearer header lets you re-run it as an authenticated portal
user to compare the two surfaces.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import xmltodict

from .constants import (
    COMMON_TABLES,
    DEFAULT_USER_AGENT,
    ERR_TABLE_PERMISSION_DENIED,
    ODATA_METADATA_PATH,
)
from .report import Finding, Report, Severity


def _as_list(value: Any) -> list:
    """xmltodict collapses single-element lists to a dict; re-expand."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@dataclass
class TableSpec:
    name: str          # entity-set name as used in the URL path
    key: str = ""
    columns: list[str] = field(default_factory=list)
    via_metadata: bool = False


@dataclass
class ProbeResult:
    table: str
    surface: str            # "odata" or "api"
    reachable: bool = False
    whole_table: bool = False
    row_seen: bool = False
    count: int | None = None
    exposed_columns: list[str] = field(default_factory=list)
    status: int | None = None
    error_code: str = ""
    error: str = ""          # transport failure: the probe never got an answer


class AnonScanner:
    def __init__(
        self,
        url: str,
        *,
        threads: int = 8,
        rate: float = 0.0,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
        probe_common: bool = True,
        verbose: bool = False,
    ) -> None:
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.rate = rate
        self.threads = max(1, threads)
        self.probe_common = probe_common
        self.verbose = verbose
        self._lock = threading.Lock()
        self._last_call = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        if extra_headers:
            self.session.headers.update(extra_headers)

    @staticmethod
    def normalize_url(url: str) -> str:
        """Add a scheme if missing and drop a trailing slash. Nothing else.

        The host is used exactly as given: a site is commonly served only under
        ``www``, where dropping the label breaks TLS (the certificate and SNI
        name no longer match) and every probe fails before it is even sent —
        which reads as "nothing is exposed" rather than "nothing was tested".
        """
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    # --- HTTP with rate limiting -------------------------------------------

    def _get(self, path: str, timeout: float | None = None) -> requests.Response:
        if self.rate > 0:
            with self._lock:
                wait = self.rate - (time.monotonic() - self._last_call)
                if wait > 0:
                    time.sleep(wait)
                self._last_call = time.monotonic()
        return self.session.get(self.url + path, timeout=timeout or self.timeout)

    # --- discovery ----------------------------------------------------------

    def discover(self, report: Report) -> list[TableSpec]:
        """Enumerate tables from the OData metadata document."""
        specs: dict[str, TableSpec] = {}
        try:
            resp = self._get(ODATA_METADATA_PATH)
        except requests.RequestException as exc:
            report.add(Finding(
                Severity.INFO, "OData metadata unreachable",
                detail=str(exc), source="anon-odata"))
            resp = None

        if resp is not None and 200 <= resp.status_code < 300 and resp.content:
            try:
                parsed = xmltodict.parse(resp.content.decode("utf-8", "replace"))
                schema = (parsed.get("edmx:Edmx", {})
                          .get("edmx:DataServices", {})
                          .get("Schema", {}))
                schema = schema[0] if isinstance(schema, list) else schema
                entity_types = _as_list(schema.get("EntityType"))
                entity_sets = _as_list(
                    (schema.get("EntityContainer") or {}).get("EntitySet"))
                # map EntityType name -> entity-set (URL) name
                type_to_set = {
                    es["@EntityType"].split(".")[-1]: es["@Name"]
                    for es in entity_sets if es.get("@EntityType")
                }
                for et in entity_types:
                    type_name = et.get("@Name", "")
                    set_name = type_to_set.get(type_name, type_name)
                    key = ((et.get("Key") or {}).get("PropertyRef") or {}).get("@Name", "")
                    cols = [p.get("@Name", "") for p in _as_list(et.get("Property"))]
                    specs[set_name] = TableSpec(set_name, key, cols, via_metadata=True)
                report.add(Finding(
                    Severity.MEDIUM,
                    "OData $metadata is anonymously readable",
                    detail=("The portal's full table/column schema is exposed to "
                            "unauthenticated callers, giving an attacker a map of "
                            "every entity set to target."),
                    source="anon-odata",
                    evidence={"tables_in_metadata": len(specs)}))
            except Exception as exc:  # malformed EDMX; keep scanning the wordlist
                report.add(Finding(
                    Severity.LOW, "Could not parse OData $metadata",
                    detail=str(exc), source="anon-odata"))

        if self.probe_common:
            for name in COMMON_TABLES:
                specs.setdefault(name, TableSpec(name))

        report.context["discovered_tables"] = sorted(specs)
        return list(specs.values())

    # --- probing ------------------------------------------------------------

    def _probe(self, spec: TableSpec, surface: str) -> ProbeResult:
        base = "/_odata/" if surface == "odata" else "/_api/"
        res = ProbeResult(table=spec.name, surface=surface)
        try:
            resp = self._get(f"{base}{spec.name}?$top=1&$count=true")
        except requests.RequestException as exc:
            res.error = str(exc)
            return res
        res.status = resp.status_code
        if 200 <= resp.status_code < 300:
            res.reachable = True
            try:
                body = resp.json()
            except ValueError:
                return res
            rows = body.get("value", [])
            res.count = body.get("@odata.count")
            res.whole_table = True
            res.row_seen = bool(rows)
            if rows:
                res.exposed_columns = sorted(rows[0].keys())
            return res
        if resp.status_code in (400, 403):
            code = ""
            try:
                code = resp.json().get("error", {}).get("code", "")
            except ValueError:
                pass
            res.error_code = code
            # Only the specific "table permission" code means the endpoint is
            # live but whole-table read is blocked — worth column probing.
            if code == ERR_TABLE_PERMISSION_DENIED and spec.columns:
                res.reachable = True
                for col in spec.columns:
                    try:
                        cr = self._get(
                            f"{base}{spec.name}?$select={col}&$top=1",
                            timeout=min(self.timeout, 6))
                    except requests.RequestException:
                        continue
                    if 200 <= cr.status_code < 300:
                        try:
                            if cr.json().get("value"):
                                res.exposed_columns.append(col)
                        except ValueError:
                            pass
        return res

    def scan(self, report: Report | None = None) -> Report:
        report = report or Report(target=self.url)
        specs = self.discover(report)
        jobs = [(s, surface) for s in specs for surface in ("odata", "api")]
        results: list[ProbeResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {pool.submit(self._probe, s, surf): (s, surf) for s, surf in jobs}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception:
                    pass
        self._record(results, report)
        return report

    def _record(self, results: list[ProbeResult], report: Report) -> None:
        answered = [r for r in results if r.status is not None]
        report.context["scan_probes"] = len(results)
        report.context["scan_unanswered"] = len(results) - len(answered)

        # Nothing answered: the site was never tested, so silence here is not
        # evidence of safety. Reporting it as a finding also makes the run fail
        # a CI gate rather than passing it on an untested target.
        if results and not answered:
            reason = next((r.error for r in results if r.error), "no response")
            report.add(Finding(
                Severity.HIGH, "Anonymous scan could not reach the site",
                detail=(f"All {len(results)} probes against {self.url} failed before "
                        "any response was received, so nothing about the site's "
                        "anonymous surface was established. This is an untested "
                        f"target, not a clean one. First error: {reason}"),
                source="anon",
                evidence={"target": self.url, "probes_attempted": len(results)}))
            report.context["anon_exposed_tables"] = []
            return

        exposed_tables: set[str] = set()
        for r in results:
            if not r.reachable and not r.exposed_columns:
                continue
            surface_label = "OData feed" if r.surface == "odata" else "Web API"
            src = "anon-odata" if r.surface == "odata" else "anon-api"
            if r.whole_table and r.row_seen:
                exposed_tables.add(r.table)
                cnt = r.count
                ev = {"columns": len(r.exposed_columns), "surface": r.surface}
                if cnt is not None:
                    ev["rows_reachable"] = cnt
                report.add(Finding(
                    Severity.CRITICAL,
                    f"Whole table readable anonymously via {surface_label}",
                    table=r.table,
                    detail=(f"GET {r.surface == 'odata' and '/_odata/' or '/_api/'}"
                            f"{r.table} returned rows with no authentication. "
                            "Every column of every in-scope record is downloadable."),
                    source=src, evidence=ev))
            elif r.whole_table and not r.row_seen:
                report.add(Finding(
                    Severity.HIGH,
                    f"Table endpoint open via {surface_label} (no rows returned now)",
                    table=r.table,
                    detail=("The endpoint answers anonymously but returned zero rows "
                            "at scan time. This is still an exposure: it will leak as "
                            "soon as the table holds in-scope data."),
                    source=src, evidence={"surface": r.surface}))
            elif r.exposed_columns:
                exposed_tables.add(r.table)
                report.add(Finding(
                    Severity.HIGH,
                    f"Column-level leak via {surface_label}",
                    table=r.table,
                    detail=("Whole-table read is blocked, but individual columns "
                            "return data when selected explicitly:\n"
                            + ", ".join(r.exposed_columns)),
                    source=src,
                    evidence={"exposed_columns": ", ".join(r.exposed_columns),
                              "surface": r.surface}))
        report.context["anon_exposed_tables"] = sorted(exposed_tables)
        if not exposed_tables and not any(
            f.severity >= Severity.HIGH for f in report.findings):
            tables = len({r.table for r in results})
            unanswered = len(results) - len(answered)
            # Say what was covered: "nothing found" is only meaningful alongside
            # how much was actually asked, and which probes never got an answer.
            detail = (f"No table returned data to an unauthenticated caller. "
                      f"{len(answered)} of {len(results)} probe(s) across {tables} "
                      "table(s) were answered by the site, over both the /_odata "
                      "feed and the /_api Web API surface.")
            if unanswered:
                detail += (f" {unanswered} probe(s) never got a response, so those "
                           "endpoints are untested rather than confirmed closed.")
            report.add(Finding(
                Severity.INFO, "No anonymously readable tables found",
                detail=detail, source="anon",
                evidence={"tables_probed": tables, "probes_answered": len(answered),
                          "probes_unanswered": unanswered}))
