import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";

const url = "https://www.roblox.com.et/login";
const snapshot = { title: "Roblox Login", headings: [{ text: "Sign in to Roblox" }], logos: [],
  page_origin: "https://www.roblox.com.et", password_fields: [{ form_index: 0 }],
  sensitive_fields: [], forms: [{ relevant: true, action_known: true,
    action_origin: "https://www.roblox.com.et" }], controls: [], inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true, candidates: token === "roblox" ?
  [{ name: "Roblox", domain: "roblox.com", verified: true, source: "test" }] : [] });
const domainLookup = async root => ({ lookup_success: true, found: false,
  registrable_domain: root, brand_name: null, brand_verified: false });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup, domainLookup,
  domainSearch: async root => ({ queried_domain: root, lookup_success: true, found: false, candidates: [] }) });
const dom = analyzeDomEvidence([snapshot]);
const original = decideWithEvidence("SAFE", dom, brand, evaluateCorrelation(dom, brand));
assert.equal(original.verdict, "DANGEROUS");
const record = { index: 1, url, expected_label: "phishing", analysis_status: "completed",
  old_verdict: original.verdict,
  analysis: { final_url: url, verdict: original.verdict, model_result: { ready: true, verdict: "SAFE" },
    dom_features: dom, brand_features: brand,
    replay_evidence: { snapshots: [snapshot], main_snapshot: snapshot, navigation: null } } };
const processResult = spawnSync("node", ["tools/replay-decisions.mjs"], {
  cwd: fileURLToPath(new URL("..", import.meta.url)),
  input: JSON.stringify({ records: [record] }), encoding: "utf8" });
assert.equal(processResult.status, 0, processResult.stderr);
const replay = JSON.parse(processResult.stdout).records[0];
assert.equal(replay.replay_level, "full_snapshot");
assert.equal(replay.new_verdict, original.verdict);
assert.deepEqual(replay.missing_saved_lookups, undefined);
console.log("Replay evidence OK: saved DOM + brand API responses reproduce the decision offline");
