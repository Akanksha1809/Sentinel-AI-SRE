#!/usr/bin/env python3
"""Record a walkthrough of the web UI for a given incident as a sequence of
screenshots, then assemble them into a GIF. Mirrors scripts/record-demo.sh's
CLI recording, but for the Phase 7 dashboard instead of the terminal.

Needs the `playwright` package and a Chromium build (not a project dependency -
deliberately run ephemerally so the main project never needs a browser):

    uvx --from playwright playwright install chromium
    uv run --with playwright python3 scripts/record-ui-demo.py <incident-ref> [out-dir]

Then stitch to GIF with ImageMagick (not done by this script, to keep it
dependency-free; `brew install imagemagick`):
    magick -delay 280 -loop 0 -resize 850x <out-dir>/*.png docs/assets/demo-ui.gif
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

SENTINEL_URL = "http://127.0.0.1:8080"
SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"


def admin_token() -> str:
    return (SECRETS_DIR / "sentinel_admin_token").read_text().strip()


def api_get(path: str, token: str) -> dict:
    # Fixed http://127.0.0.1 prefix (SENTINEL_URL), never a user-controlled scheme.
    req = urllib.request.Request(  # noqa: S310 # nosec B310
        f"{SENTINEL_URL}{path}", headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 # nosec B310
        return json.load(r)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: record-ui-demo.py <incident-ref> [out-dir]", file=sys.stderr)
        return 1
    ref = sys.argv[1]
    default_out = Path.home() / ".cache" / "sentinel-ui-demo"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else default_out
    out_dir.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright

    token = admin_token()
    actions = api_get(f"/api/v1/incidents/{ref}/actions", token)
    action_id = actions[0]["id"] if actions else None

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1100, "height": 760})

        page.goto(f"{SENTINEL_URL}/login")
        page.fill("#token", token)
        page.click("button[type=submit]")
        page.wait_for_url(f"{SENTINEL_URL}/")
        page.screenshot(path=str(out_dir / "1-incidents.png"))

        page.goto(f"{SENTINEL_URL}/incidents/{ref}")
        page.screenshot(path=str(out_dir / "2-observations.png"))

        page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.45)")
        page.screenshot(path=str(out_dir / "3-hypotheses.png"))

        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.screenshot(path=str(out_dir / "4-remediation.png"))

        if action_id:
            page.goto(f"{SENTINEL_URL}/actions/{action_id}")
            page.screenshot(path=str(out_dir / "5-approval.png"))

        browser.close()

    print(f"Screenshots in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
