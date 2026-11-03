from pathlib import Path
from playwright.sync_api import sync_playwright

script = Path(__file__).resolve().parents[1] / "src/content/dom-brand-observer.js"
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.route("https://shop.test/**", lambda route: route.fulfill(status=200, content_type="text/html", body="<html><head><title>Shop</title></head><body><main><button>Continue with Google</button></main></body></html>"))
    page.goto("https://shop.test/")
    page.evaluate("""() => { window.chrome = { runtime: { onMessage: { addListener(fn) { window.hsListener = fn; } }, sendMessage() { return Promise.resolve({ok:true}); } } }; }""")
    page.add_script_tag(path=str(script))
    snapshot = page.evaluate("""() => { let result; window.hsListener({type:'HEURISHIELD_COLLECT_EVIDENCE'}, null, value => result=value); return result.snapshot; }""")
    assert snapshot["controls"][0]["type"] == "oauth_login", snapshot
    assert snapshot["password_fields"] == [], snapshot
    page.evaluate("""() => { const root=document.createElement('div'); document.body.append(root); const shadow=root.attachShadow({mode:'open'}); shadow.innerHTML='<form action="/account"><input type="password" autocomplete="current-password"><input name="otp" autocomplete="one-time-code"><button>Login</button></form>'; }""")
    page.wait_for_timeout(900)
    snapshot = page.evaluate("""() => { let result; window.hsListener({type:'HEURISHIELD_COLLECT_EVIDENCE'}, null, value => result=value); return result.snapshot; }""")
    assert len(snapshot["password_fields"]) == 1, snapshot
    assert snapshot["sensitive_fields"][0]["type"] == "otp", snapshot
    assert snapshot["forms"][0]["action_origin"] == "https://shop.test", snapshot
    print("Browser DOM smoke OK: OAuth button, dynamic Shadow DOM, password, OTP, relative form")
    browser.close()
