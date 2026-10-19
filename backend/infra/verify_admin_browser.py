"""Browser regression for a delayed 401 arriving after a successful new login.

Run: uv run --with playwright python infra/verify_admin_browser.py
All API requests are mocked; no AWS accounts or credentials are used.
"""

import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
ORIGIN = "https://admin.test"


def main():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        errors = []
        pending = {}
        logins = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def reply(route, data, status=200):
            route.fulfill(status=status, content_type="application/json", body=json.dumps(data))

        def handle(route):
            request = route.request
            path = request.url.removeprefix(ORIGIN)
            if not path.startswith("/api/"):
                name = path.lstrip("/")
                if name == "config.js":
                    route.fulfill(
                        content_type="application/javascript",
                        body='window.SD_CONFIG = {apiBase: "https://api.invalid", adminApiBase: ""};',
                    )
                else:
                    route.fulfill(path=str(FRONTEND / name))
                return
            token = request.headers.get("authorization")
            if path == "/api/admin/login":
                logins.append(route)
            elif path.startswith("/api/admin/stats"):
                if token == "Bearer old":
                    pending[path] = route
                elif token == "Bearer new":
                    reply(route, {"by_event": {}, "by_type": {}, "by_source": {}})
                else:
                    reply(route, {}, 401)
            else:
                reply(route, {"items": []})

        page.route(ORIGIN + "/**", handle)
        page.add_init_script("""sessionStorage.setItem('sd_admin_session', JSON.stringify({
            token: 'old', expires_at: '2099-01-01T00:00:00Z'
        }));""")
        page.goto(ORIGIN + "/admin.html")
        page.wait_for_function("document.querySelector('#days').value === '1'")
        page.locator("#days").select_option("7")
        page.wait_for_timeout(100)
        assert len(pending) == 2
        reply(pending["/api/admin/stats?days=1"], {}, 401)
        expect(page.locator("#login-view")).to_be_visible()
        page.locator("#username").fill("operator")
        page.locator("#password").fill("mock-password")
        page.locator('button[type="submit"]').click()
        expect(page.locator('button[type="submit"]')).to_be_disabled()
        page.locator("#login-form").evaluate("form => form.requestSubmit()")
        page.wait_for_timeout(100)
        assert len(logins) == 1
        reply(logins[0], {"token": "new", "expires_at": "2099-01-01T00:00:00Z"})
        expect(page.locator("#console-view")).to_be_visible()
        reply(pending["/api/admin/stats?days=7"], {}, 401)
        page.wait_for_timeout(200)
        expect(page.locator("#console-view")).to_be_visible()
        assert page.evaluate("JSON.parse(sessionStorage.getItem('sd_admin_session')).token") == "new"

        # A 401 for the current session must still require login.
        page.route(ORIGIN + "/api/admin/stats*", lambda route: reply(route, {}, 401))
        page.locator("#refresh").click()
        expect(page.locator("#login-view")).to_be_visible()
        expect(page.locator("#login-msg")).to_contain_text("세션이 만료")
        assert page.evaluate("sessionStorage.getItem('sd_admin_session')") is None
        assert not errors, errors
        browser.close()
    print("Passed: delayed old 401, duplicate login, current session expiry")


if __name__ == "__main__":
    main()
