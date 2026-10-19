"""Verify deployed admin login using installed Chrome, including API forwarding.

Run: uv run --with playwright python infra/verify_admin_live.py
Credentials come from SD_ADMIN_USERNAME / SD_ADMIN_PASSWORD or hidden input.
Only status codes and request IDs are printed; no tokens or passwords are saved.
"""

import argparse
import getpass
import json
import os
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://securedrop.ldh.mzsec.cloud")
    parser.add_argument("--channel", default="chrome")
    args = parser.parse_args()
    username = os.environ.get("SD_ADMIN_USERNAME", "operator")
    password = os.environ.get("SD_ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
    responses = []
    errors = []
    origin = args.url.rstrip("/")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=args.channel)
        page = browser.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))

        def response_received(response):
            if "/api/admin/" in response.url and response.request.method != "OPTIONS":
                assert urlsplit(response.url).netloc == urlsplit(origin).netloc
                responses.append(
                    {
                        "path": urlsplit(response.url).path,
                        "status": response.status,
                        "request_id": response.headers.get("x-amzn-requestid"),
                    }
                )

        page.on("response", response_received)
        page.goto(origin + "/admin.html")
        page.locator("#username").fill(username)
        page.locator("#password").fill(password)
        try:
            with page.expect_response(lambda r: "/api/admin/transfers?" in r.url):
                page.locator('button[type="submit"]').click()
            expect(page.locator("#console-view")).to_be_visible()
            expect(page.locator("#by-event .card")).to_have_count(6)
            expect(page.locator("#console-msg")).to_be_empty()
            with page.expect_response(lambda r: "/api/admin/transfers?" in r.url):
                page.reload()
            expect(page.locator("#by-event .card")).to_have_count(6)
            with page.expect_response(lambda r: "/api/admin/transfers?" in r.url):
                page.locator("#refresh").click()
            expect(page.locator("#console-view")).to_be_visible()
            with page.expect_response(lambda r: "/api/admin/stats?days=7" in r.url):
                page.locator("#days").select_option("7")
            expect(page.locator("#console-msg")).to_be_empty()
        finally:
            if page.evaluate("sessionStorage.getItem('sd_admin_session') !== null"):
                page.locator("#logout").click()
                expect(page.locator("#login-view")).to_be_visible()
            browser.close()
    assert not errors, errors
    assert responses and all(r["status"] == 200 for r in responses), responses
    print(json.dumps({"browser": args.channel, "responses": responses}, indent=2))


if __name__ == "__main__":
    main()
