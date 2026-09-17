"""Screenshot the sample HTML report for the README.

Run ``build_mockup.py`` first. Uses Playwright driving the locally installed
Chrome (``channel="chrome"``), so no browser download is needed; pass
``--bundled`` to use Playwright's own Chromium instead.

    python mockup/capture.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
REPORT = HERE / "sample_report.html"
OUT = HERE / "_img"

WIDTH = 1280
SCALE = 1.5


def _tab(page, name: str) -> None:
    page.click(f"#tab-{name}")
    page.wait_for_selector(f"#panel-{name}:not([hidden])")


def main() -> None:
    if not REPORT.is_file():
        raise SystemExit("sample_report.html missing: run mockup/build_mockup.py first")
    OUT.mkdir(exist_ok=True)
    launch = {} if "--bundled" in sys.argv else {"channel": "chrome"}

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch)
        page = browser.new_page(viewport={"width": WIDTH, "height": 900},
                                device_scale_factor=SCALE, locale="en-GB",
                                timezone_id="Pacific/Auckland")
        page.goto(REPORT.as_uri())

        # 1. Masthead, tabs, severity counts and the Critical items requiring
        #    action — cut on a row boundary so the list does not end mid-item.
        criticals = page.locator("#summary .action-list li",
                                 has=page.locator(".badge.sev-critical"))
        last = criticals.nth(criticals.count() - 1).bounding_box()
        page.screenshot(path=OUT / "overview.png", full_page=True,
                        clip={"x": 0, "y": 0, "width": WIDTH,
                              "height": last["y"] + last["height"]})

        # 2. The headline finding: a page rendering personal data to anyone.
        _tab(page, "findings")
        finding = page.locator("article.finding", has_text=(
            "Unprotected page renders anonymously-readable data")).first
        finding.locator("details.query").evaluate("d => d.open = true")
        finding.screenshot(path=OUT / "finding.png")

        # 3. What the public can read, per table.
        _tab(page, "anonymous")
        page.locator("#anonymous").screenshot(path=OUT / "anonymous-access.png")

        # 4. Where each table is rendered, with the query that does it.
        _tab(page, "rendered")
        ref = page.locator("details.ref", has_text="cr7f3_eventregistration").first
        ref.evaluate("d => { d.open = true; "
                     "d.querySelectorAll('details').forEach(q => q.open = true); }")
        ref.screenshot(path=OUT / "where-rendered.png")

        # 5. Live URLs with what an anonymous GET actually returned.
        _tab(page, "published")
        page.locator("#published").screenshot(path=OUT / "published-urls.png")

        # 6. The configuration inventory a reviewer checks against intent.
        _tab(page, "configuration")
        page.locator("#configuration").screenshot(path=OUT / "configuration.png")

        browser.close()

    for image in sorted(OUT.glob("*.png")):
        print(f"{image.relative_to(HERE.parent)}  {image.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
