"""Microsoft Learn references for each class of finding.

A finding that says what is wrong but not how to fix it forces the reader to go
looking. Every title the audit can emit is mapped here to the official
documentation for the feature involved, so the report carries its own
remediation path.

URLs are locale-neutral (no ``/en-us/``) so Learn redirects readers to their own
language. All were verified live when added; :func:`iter_links` exists so a
test or a maintainer can re-check them in one pass.
"""

from __future__ import annotations

from typing import Iterator, NamedTuple


class DocLink(NamedTuple):
    title: str
    url: str


LEARN = "https://learn.microsoft.com"

# Individual pages, so the same reference can serve several finding titles.
TABLE_PERMISSIONS = DocLink(
    "Configure table permissions", f"{LEARN}/power-pages/security/table-permissions")
ACCESS_TYPES = DocLink(
    "Table permission access types (scope)",
    f"{LEARN}/power-pages/security/table-permissions#available-access-types")
ASSIGN_PERMISSIONS = DocLink(
    "Assign table permissions to web roles",
    f"{LEARN}/power-pages/security/assign-table-permissions")
WEB_ROLES = DocLink(
    "Create and manage web roles", f"{LEARN}/power-pages/security/create-web-roles")
COLUMN_PERMISSIONS = DocLink(
    "Column permissions", f"{LEARN}/power-pages/security/column-permissions")
COLUMN_SECURITY_PROFILE = DocLink(
    "Column security profiles (enhanced model)",
    f"{LEARN}/power-pages/security/column-security-profile")
PAGE_SECURITY = DocLink(
    "Page permissions", f"{LEARN}/power-pages/security/page-security")
BEST_PRACTICES = DocLink(
    "Power Pages security best practices",
    f"{LEARN}/power-pages/security/security-best-practices")
SECURITY_OVERVIEW = DocLink(
    "Power Pages security overview",
    f"{LEARN}/power-pages/security/power-pages-security")
WEB_API = DocLink(
    "Power Pages Web API overview", f"{LEARN}/power-pages/configure/web-api-overview")
WEB_API_HOWTO = DocLink(
    "Configure the Web API site settings",
    f"{LEARN}/power-pages/configure/webapi-how-to")
WEB_API_WILDCARD = DocLink(
    "Replace the Web API fields wildcard",
    f"{LEARN}/troubleshoot/power-platform/power-pages/migrate-web-api-wildcard")
ENHANCED_MODEL = DocLink(
    "Standard vs enhanced data model",
    f"{LEARN}/power-pages/admin/enhanced-data-model")
AUTHENTICATION = DocLink(
    "Configure authentication", f"{LEARN}/power-pages/security/authentication/")
DISPLAY_SECURELY = DocLink(
    "Tutorial: display data securely",
    f"{LEARN}/power-pages/getting-started/tutorial-display-data-securely")
PRIVACY = DocLink(
    "Implement privacy and personal data handling",
    f"{LEARN}/power-pages/configure/implement-privacy")

# Finding title -> the pages that help fix it. Titles are matched exactly first,
# then by prefix, so parameterised titles ("Anonymous read with Self scope")
# still resolve.
FINDING_DOCS: dict[str, list[DocLink]] = {
    "Anonymous global read of a table": [ACCESS_TYPES, DISPLAY_SECURELY, BEST_PRACTICES],
    "Anonymous data modification permitted": [ACCESS_TYPES, TABLE_PERMISSIONS,
                                              BEST_PRACTICES],
    "Anonymous read with": [ACCESS_TYPES, TABLE_PERMISSIONS],
    "Anonymous Users role identified": [WEB_ROLES, ASSIGN_PERMISSIONS],
    "No Anonymous Users role is defined": [WEB_ROLES],
    "Multiple Anonymous Users roles": [WEB_ROLES],
    "Multiple Authenticated Users roles": [WEB_ROLES],
    "One web role serves both anonymous and signed-in users": [WEB_ROLES,
                                                               ASSIGN_PERMISSIONS],
    "Table permission bound to no web role": [ASSIGN_PERMISSIONS, TABLE_PERMISSIONS],
    "Table permission has no access type set": [ACCESS_TYPES],
    "Web API publishes every column of a table": [WEB_API_WILDCARD, WEB_API_HOWTO,
                                                  COLUMN_PERMISSIONS],
    "Web API fields wildcard is deprecated": [WEB_API_WILDCARD, WEB_API_HOWTO,
                                              COLUMN_PERMISSIONS],
    "Web API enabled for table": [WEB_API, WEB_API_HOWTO],
    "Web API is not enabled for any table": [WEB_API],
    "Profile grants Create/Update on all columns": [COLUMN_PERMISSIONS],
    "Column permissions may not be enforced on this site": [COLUMN_SECURITY_PROFILE,
                                                            ENHANCED_MODEL],
    "Entity list publishes an OData feed": [BEST_PRACTICES, TABLE_PERMISSIONS],
    "Site setting weakens the security posture": [BEST_PRACTICES, SECURITY_OVERVIEW],
    "Authenticated-role access with open self-registration": [AUTHENTICATION,
                                                              BEST_PRACTICES],
    "Both Power Pages configuration models are present": [ENHANCED_MODEL],
    "Standard data model configuration read": [ENHANCED_MODEL],
    "Enhanced data model configuration read": [ENHANCED_MODEL],
    "External leak tied to configured permissions": [ACCESS_TYPES, BEST_PRACTICES],
    "External leak with no matching table permission": [BEST_PRACTICES, WEB_API,
                                                        PAGE_SECURITY],
    "Anonymous OData metadata is readable": [BEST_PRACTICES, WEB_API],
    "Personal data reachable anonymously": [PRIVACY, ACCESS_TYPES],
}

# Always shown in the report's own help section.
GENERAL_DOCS: list[DocLink] = [
    SECURITY_OVERVIEW, BEST_PRACTICES, TABLE_PERMISSIONS, ACCESS_TYPES,
    WEB_ROLES, COLUMN_PERMISSIONS, PAGE_SECURITY, WEB_API, ENHANCED_MODEL, PRIVACY,
]


def for_finding(title: str) -> list[DocLink]:
    """Documentation for a finding title, falling back to a prefix match."""
    exact = FINDING_DOCS.get(title)
    if exact:
        return exact
    for key, links in FINDING_DOCS.items():
        if title.startswith(key):
            return links
    return []


def iter_links() -> Iterator[DocLink]:
    """Every distinct link, for link-checking."""
    seen: set[str] = set()
    for links in list(FINDING_DOCS.values()) + [GENERAL_DOCS]:
        for link in links:
            if link.url not in seen:
                seen.add(link.url)
                yield link
