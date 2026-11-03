from pathlib import Path
from tempfile import TemporaryDirectory
import json
from playwright.sync_api import sync_playwright

extension = Path(__file__).resolve().parents[1]
with TemporaryDirectory(prefix="hs-extension-smoke-") as profile, sync_playwright() as p:
    context = p.chromium.launch_persistent_context(
        profile, headless=True,
        channel="chromium",
        args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}"],
    )
    worker = context.service_workers[0] if context.service_workers else context.wait_for_event("serviceworker", timeout=10000)
    assert worker.url.endswith("/src/background/service-worker.js"), worker.url
    assert worker.evaluate("() => typeof chrome.runtime.id === 'string'")
    expected_version = json.loads((extension / "manifest.json").read_text(encoding="utf-8"))["version"]
    assert worker.evaluate("() => chrome.runtime.getManifest().version") == expected_version
    worker.evaluate("async () => chrome.storage.local.set({heurishieldEnabled:false})")
    context.route("https://shop.example.test/**", lambda route: route.fulfill(status=200, content_type="text/html", body="<html><head><title>Google Login</title></head><body><main><h1>Sign in to Google</h1><form><input type='password' autocomplete='current-password'><button>Login</button></form></main></body></html>"))
    page = context.new_page()
    page.goto("https://shop.example.test/login")
    snapshot = worker.evaluate("""async () => {
      const [tab] = await chrome.tabs.query({url:'https://shop.example.test/*'});
      if (!tab) throw new Error('Test tab missing');
      return chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_COLLECT_EVIDENCE'}, {frameId:0});
    }""")
    assert snapshot["ok"] and snapshot["snapshot"]["password_fields"], snapshot
    assert snapshot["snapshot"]["title"] == "Google Login", snapshot
    worker.evaluate("""async () => {
      const [tab] = await chrome.tabs.query({url:'https://shop.example.test/*'});
      await chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_ANALYSIS_UPDATED', analysis: {
        verdict:'SAFE', hostname:'shop.example.test', registrable_domain:'dicoding.com',
        final_url:'https://shop.example.test/login',
        model_result:{ready:true,model_family:'XGBoost'},
        brand_features:{claimed_brand:{name:'YouTube'},official_domain_match:true},
        explanation:{summary:'Pemeriksaan selesai',reasons:['Domain resmi cocok'],action:'Periksa alamat'}
      }});
    }""")
    page.wait_for_timeout(200)
    snapshot_dom = context.new_cdp_session(page).send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
    assert "YouTube" in snapshot_dom["strings"], "Brand result did not appear in overlay"
    assert "shop.example.test" in snapshot_dom["strings"], "Displayed domain must come from the current page"
    assert "dicoding.com" not in snapshot_dom["strings"], "Stale source domain leaked into the panel"
    assert "YouTube · domain cocok" not in snapshot_dom["strings"]
    worker.evaluate("""async () => {
      const [tab] = await chrome.tabs.query({url:'https://shop.example.test/*'});
      await chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_ANALYSIS_UPDATED', analysis: {
        verdict:'DANGEROUS', model_result:{ready:true,model_family:'XGBoost'},
        brand_features:{claimed_brand:{name:'Roblox'},
          high_confidence_host_impersonation:true,brand_claim_relation:'external_domain'}
      }});
    }""")
    page.wait_for_timeout(100)
    snapshot_dom = context.new_cdp_session(page).send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
    assert "Impersonate (Roblox)" in snapshot_dom["strings"]
    worker.evaluate("""async () => {
      const [tab] = await chrome.tabs.query({url:'https://shop.example.test/*'});
      await chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_ANALYSIS_UPDATED', analysis: {
        verdict:'SAFE', model_result:{ready:true,model_family:'XGBoost'},
        brand_features:{claimed_brand_status:'unknown',candidates:[
          {name:'Instagram',verified:true,in_title:true,in_heading:false,in_logo:false}]}
      }});
    }""")
    page.wait_for_timeout(100)
    snapshot_dom = context.new_cdp_session(page).send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
    assert "Instagram · belum terverifikasi" in snapshot_dom["strings"], "Unverified page candidate was hidden"
    print("Manifest V3 extension loaded; DOM extracted and brand result rendered in overlay")
    context.close()
