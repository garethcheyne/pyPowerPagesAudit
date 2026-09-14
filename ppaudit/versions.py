"""Checks the environment against Microsoft's published Power Pages releases.

The tool must not carry a hardcoded "current version": it would be wrong within
a month. Microsoft publishes the release list, so the reference point is fetched
from there and the report states where it came from.

Two different version schemes are in play, and conflating them gives the wrong
answer:

* the **website host** — Azure-side, numbered ``9.8.8.x``, updated automatically
  by Microsoft, published at :data:`RELEASED_VERSIONS_URL`;
* the **Dataverse solutions** — numbered ``9.3.YYMM.x``, the customer's
  responsibility, and what actually goes stale.

The published host release gives a dated reference point to measure the
solutions against, which beats an arbitrary "two years old" threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

RELEASED_VERSIONS_URL = (
    "https://learn.microsoft.com/power-platform/released-versions/portals/")

_MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"], 1)}

# "Power Pages Update 9.8.8.x" ... "August 2026", in the published table.
_ROW = re.compile(
    r"Power Pages Update\s+([\d.]+x)\s*</a>\s*</td>\s*<td[^>]*>\s*"
    r"([A-Za-z]+)\s+(\d{4})", re.I | re.S)
_ROW_LOOSE = re.compile(
    r"Power Pages Update\s+([\d.]+x).{0,400?}?([A-Za-z]+)\s+(\d{4})", re.I | re.S)


@dataclass
class Release:
    version: str
    released: date
    source: str = RELEASED_VERSIONS_URL

    @property
    def label(self) -> str:
        return f"{self.version} ({self.released.strftime('%B %Y')})"


def parse_releases(html: str) -> list[Release]:
    """Extract the published release list, newest first."""
    seen: dict[str, Release] = {}
    for pattern in (_ROW, _ROW_LOOSE):
        for version, month, year in pattern.findall(html):
            index = _MONTHS.get(month.lower())
            if not index or version in seen:
                continue
            seen[version] = Release(version=version,
                                    released=date(int(year), index, 1))
        if seen:
            break
    return sorted(seen.values(), key=lambda r: r.released, reverse=True)


def fetch_current_release(timeout: float = 20.0) -> Release | None:
    """The newest published Power Pages release, or None if it cannot be read.

    Never fatal: a version check is context, and an audit must still run on a
    machine with no outbound internet access.
    """
    try:
        import requests

        resp = requests.get(RELEASED_VERSIONS_URL, timeout=timeout,
                            headers={"User-Agent": "ppaudit"})
        if resp.status_code != 200:
            return None
        releases = parse_releases(resp.text)
        return releases[0] if releases else None
    except Exception:
        return None
