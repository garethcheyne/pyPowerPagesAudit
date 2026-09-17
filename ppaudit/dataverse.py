"""Authenticated Dataverse Web API client (app-registration / client credentials).

Auth is Azure AD OAuth2 client-credentials only, per the audit's design:
supply ``TENANT_ID``, ``CLIENT_ID`` and ``CLIENT_SECRET`` (env vars or
constructor args). The app registration must be added to the target
environment as an **Application User** with a security role that can read the
Power Pages configuration tables (System Administrator, or a custom role with
read on ``adx_*`` / ``mspp_*`` config entities).

The client is deliberately small: token acquisition, a paged ``GET`` helper
that follows ``@odata.nextLink``, and detection of which configuration schema
generation (``adx_`` vs ``mspp_``) the environment uses.
"""

from __future__ import annotations

import os
import time
from typing import Any, Iterator

import requests

from .constants import AAD_TOKEN_ENDPOINT, CONFIG_SCHEMAS, DATAVERSE_API_VERSION


class DataverseError(RuntimeError):
    pass


class DataverseClient:
    def __init__(
        self,
        org_url: str,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.org_url = org_url.rstrip("/")
        self.api_root = f"{self.org_url}/api/data/{DATAVERSE_API_VERSION}"
        self.tenant_id = tenant_id or os.environ.get("TENANT_ID", "")
        self.client_id = client_id or os.environ.get("CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("CLIENT_SECRET", "")
        self.timeout = timeout
        self._token = ""
        self._token_exp = 0.0
        self.session = requests.Session()
        if not all((self.tenant_id, self.client_id, self.client_secret)):
            raise DataverseError(
                "Missing credentials. Provide tenant_id/client_id/client_secret "
                "or set TENANT_ID / CLIENT_ID / CLIENT_SECRET.")

    # --- auth ---------------------------------------------------------------

    def _acquire_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        resp = requests.post(
            AAD_TOKEN_ENDPOINT.format(tenant=self.tenant_id),
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
                "scope": f"{self.org_url}/.default",
            },
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise DataverseError(
                f"Token request failed ({resp.status_code}): {resp.text[:400]}")
        body = resp.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._acquire_token()}",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
            # Ask the server for formatted option-set labels so we do not have
            # to hardcode scope option-set integers.
            "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        }

    # --- queries ------------------------------------------------------------

    def get(self, entity_set: str, query: str = "") -> Iterator[dict[str, Any]]:
        """Yield all rows of a query, following server-side paging."""
        url = f"{self.api_root}/{entity_set}"
        if query:
            url += ("&" if "?" in url else "?") + query
        while url:
            resp = self.session.get(url, headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 404:
                raise DataverseError(f"Entity set not found: {entity_set}")
            if resp.status_code != 200:
                raise DataverseError(
                    f"Query failed ({resp.status_code}) for {entity_set}: "
                    f"{resp.text[:400]}")
            body = resp.json()
            yield from body.get("value", [])
            url = body.get("@odata.nextLink")

    def entity_set_exists(self, entity_set: str) -> bool:
        try:
            next(self.get(entity_set, "$top=1"), None)
            return True
        except DataverseError:
            return False

    def try_get(self, entity_set: str, query: str = "") -> tuple[list[dict[str, Any]], str]:
        """Non-fatal fetch: return (rows, error_message).

        Config tables are small and several are optional (column permissions
        and entity lists may simply not exist in a given environment), so the
        audit must degrade rather than abort when one is unreadable.
        """
        try:
            return list(self.get(entity_set, query)), ""
        except DataverseError as exc:
            return [], str(exc)

    # --- metadata ------------------------------------------------------------

    def string_max_length(self, entity: str, attribute: str) -> int | None:
        """MaxLength of a string column, or None if it cannot be read.

        Name fields are customisable per environment, so the limit has to come
        from the target rather than a constant.
        """
        query = (f"EntityDefinitions(LogicalName='{entity}')/Attributes/"
                 "Microsoft.Dynamics.CRM.StringAttributeMetadata"
                 "?$select=LogicalName,MaxLength")
        try:
            for row in self.get(query):
                if row.get("LogicalName") == attribute:
                    return int(row["MaxLength"])
        except (DataverseError, KeyError, TypeError, ValueError):
            return None
        return None

    def entity_set_names(self) -> dict[str, str]:
        """Map each table's logical name to its Web API entity-set name.

        The Web API and OData paths address a table by its *entity set* name
        (``contacts``), not its logical name (``contact``); the two differ by
        more than an ``s`` for irregular plurals, so the mapping has to come
        from the environment rather than be guessed.
        """
        out: dict[str, str] = {}
        try:
            for row in self.get("EntityDefinitions", "$select=LogicalName,EntitySetName"):
                logical = row.get("LogicalName")
                entity_set = row.get("EntitySetName")
                if logical and entity_set:
                    out[logical] = entity_set
        except DataverseError:
            pass
        return out

    def portal_solutions(self) -> list[dict[str, Any]]:
        """Installed Power Pages solutions and their versions.

        These are the versions the Power Platform admin centre shows. They
        matter for security: the website host updates itself, but the Dataverse
        solutions do not, and Microsoft does not certify an unsupported solution
        version to run against a current host.
        """
        query = ("solutions?$select=uniquename,friendlyname,version,installedon"
                 "&$filter=ismanaged eq true and ("
                 "contains(uniquename,'Portal') or contains(uniquename,'portal'))"
                 "&$orderby=uniquename")
        rows, _ = self.try_get(query)
        return rows

    # --- writes -------------------------------------------------------------

    def patch(self, entity_set: str, record_id: str, body: dict[str, Any]) -> None:
        """Update one record. The only write this tool performs.

        ``If-Match: *`` makes it an update-only request: without it Dataverse
        would upsert, creating a record if the id were wrong.
        """
        url = f"{self.api_root}/{entity_set}({record_id})"
        headers = self._headers() | {
            "Content-Type": "application/json",
            "If-Match": "*",
        }
        resp = self.session.patch(url, headers=headers, json=body, timeout=self.timeout)
        if resp.status_code not in (200, 204):
            raise DataverseError(
                f"Update failed ({resp.status_code}) for {entity_set}({record_id}): "
                f"{resp.text[:400]}")

    def detect_schemas(self) -> list[tuple[str, dict[str, Any]]]:
        """Return every configuration generation readable in this environment.

        Enhanced-data-model sites expose ``mspp_*`` virtual tables; standard
        (classic Portals) sites expose physical ``adx_*`` tables. Environments
        that were upgraded in place often carry both, and both must be audited
        because either can grant access.
        """
        found: list[tuple[str, dict[str, Any]]] = []
        for gen in ("mspp", "adx"):
            cfg = CONFIG_SCHEMAS[gen]
            if self.entity_set_exists(cfg["sets"]["webrole"]):
                found.append((gen, cfg))
        if not found:
            raise DataverseError(
                "Neither mspp_webroles (enhanced data model) nor adx_webroles "
                "(standard data model) is readable. Confirm the application user "
                "has read access to the Power Pages configuration tables.")
        return found

    def whoami(self) -> dict[str, Any]:
        resp = self.session.get(
            f"{self.api_root}/WhoAmI", headers=self._headers(), timeout=self.timeout)
        if resp.status_code != 200:
            raise DataverseError(f"WhoAmI failed ({resp.status_code}): {resp.text[:200]}")
        return resp.json()
