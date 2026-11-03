"""Observe a controlled SPA fixture, without visiting public websites or APIs."""
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

extension = Path(__file__).resolve().parents[1]
with TemporaryDirectory(prefix='hs-spa-fixture-') as profile, sync_playwright() as p:
    context = p.chromium.launch_persistent_context(profile, headless=True, channel='chromium',
        args=[f'--disable-extensions-except={extension}', f'--load-extension={extension}'])
    worker = context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
    worker.evaluate('async () => chrome.storage.local.set({heurishieldEnabled:false})')
    context.route('https://spa.example.test/**', lambda route: route.fulfill(status=200,
        content_type='text/html', body='<html><head><title></title></head><body><main></main></body></html>'))
    page = context.new_page()
    page.goto('https://spa.example.test/')
    def snapshot():
        return worker.evaluate('''async () => {
          const [tab] = await chrome.tabs.query({url:'https://spa.example.test/*'});
          return (await chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_COLLECT_EVIDENCE'}, {frameId:0})).snapshot;
        }''')
    before = snapshot()
    assert before['evidence_incomplete'] is True
    page.evaluate('''() => {
      document.title = 'Account login';
      document.querySelector('main').innerHTML = '<h1>Account</h1><form><input type="text" name="identity"><button>Login</button></form>';
      document.querySelector('input').type = 'password';
    }''')
    after = snapshot()
    assert after['evidence_incomplete'] is False
    assert after['password_fields'] and after['forms'][0]['relevant']
    assert after['title'] == 'Account login'
    page.evaluate("() => document.querySelector('input').setAttribute('autocomplete','one-time-code')")
    assert snapshot()['password_fields']
    print('SPA fixture: empty initial document, text/title update, form insertion and password type change observed')
    context.close()
