import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/content/score-overlay.js', import.meta.url), 'utf8');
const nodes = new Map();
class Element {
  constructor() { this.listeners = {}; this.dataset = {}; }
  querySelector(selector) {
    if (!nodes.has(selector)) nodes.set(selector, new Element());
    return nodes.get(selector);
  }
  attachShadow() { return new Element(); }
  append() {}
  replaceChildren() {}
  setAttribute() {}
  addEventListener(event, handler) { this.listeners[event] = handler; }
}
const calls = [];
let mode = 'ok';
let reloads = 0;
const runtime = {
  id: 'test', onMessage: { addListener() {} },
  sendMessage(message) {
    calls.push(message.type);
    if (mode === 'throw') throw new Error('Extension context invalidated.');
    if (mode === 'reject') return Promise.reject(new Error('Extension context invalidated.'));
    return Promise.resolve({ ok: true, analysis: { verdict: 'SAFE' } });
  }
};
vm.runInNewContext(source, {
  document: { createElement: () => new Element(), readyState: 'complete', documentElement: new Element() },
  chrome: { runtime }, location: { href: 'https://example.org/', protocol: 'https:', hostname: 'example.org', reload: () => { reloads++; } },
  URL, console
});
const flush = () => new Promise(resolve => setImmediate(resolve));
await flush();
assert.equal(nodes.get('.hs-verdict').textContent, 'Legitimate');
for (const failure of ['throw', 'reject', 'missing-id']) {
  mode = failure === 'missing-id' ? 'ok' : failure;
  runtime.id = failure === 'missing-id' ? undefined : 'test';
  for (const selector of ['.hs-options', '.hs-history', '.hs-allow-list', '.hs-block-list']) {
    const before = calls.length;
    await nodes.get(selector).listeners.click();
    await flush();
    assert.match(nodes.get('.hs-summary').textContent, /Muat ulang halaman/);
    assert.equal(nodes.get('.hs-panel').hidden, false);
    assert.equal(nodes.get('.hs-verdict').textContent, 'Gagal');
    assert.equal(calls.length - before, failure === 'missing-id' ? 0 : 1);
  }
}
const beforeReload = calls.length;
await nodes.get('.hs-refresh').listeners.click(); await flush();
assert.equal(reloads, 1);
assert.equal(calls.length, beforeReload);
assert.equal(nodes.get('.hs-refresh').textContent, 'Muat ulang halaman');
console.log('PASS: overlay handles synchronous throws, rejected promises and missing runtime ID; recovery reloads the page without calling invalid runtime.');
