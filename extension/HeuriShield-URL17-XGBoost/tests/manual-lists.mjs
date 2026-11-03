import assert from "node:assert/strict";
const store = new Map();
globalThis.chrome = { storage: { local: {
  async get(values) { return Object.fromEntries(Object.entries(values).map(([key, fallback]) =>
    [key, store.has(key) ? store.get(key) : fallback])); },
  async set(values) { for (const [key, value] of Object.entries(values)) store.set(key, value); }
} } };
const settings = await import("../src/storage/settings.js");
assert.equal(settings.normalizeManualDomain("https://www.example.test/login"), "example.test");
assert.equal(settings.normalizeManualDomain("portal.example.test"), "portal.example.test");
await settings.addToAllowlist("https://www.example.test/login");
assert.deepEqual(await settings.getAllowlist(), ["example.test"]);
await settings.addToBlacklist("www.example.test");
assert.deepEqual(await settings.getBlacklist(), ["example.test"]);
assert.deepEqual(await settings.getAllowlist(), []);
await settings.addToAllowlist("portal.example.test");
assert.deepEqual(await settings.getAllowlist(), ["portal.example.test"]);
assert.deepEqual(await settings.getBlacklist(), ["example.test"]);
console.log("Manual list storage and www normalization OK");
