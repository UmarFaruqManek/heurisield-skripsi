import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mergeDatasetRows, writeDatasetFile } from '../src/storage/dataset-file.js';
const { features } = JSON.parse(await readFile(new URL('../src/rule/feature-contract-60.json', import.meta.url)));
const row = { url: 'https://example.org/account', ...Object.fromEntries(features.map(f => [f, null])), label: 'legitimate' };
const second = { ...row, url: 'https://example.net/verify', label: 'phishing' };
let content = JSON.stringify([row]);
let permission = 'granted'; let writeCount = 0;
const handle = {
  queryPermission: async () => permission,
  getFile: async () => ({ text: async () => content }),
  createWritable: async () => {
    let pending;
    return { write: async text => { pending = text; }, close: async () => { content = pending; writeCount++; }, abort: async () => {} };
  }
};
assert.equal(await writeDatasetFile(handle, [row, second], features), 2);
assert.deepEqual(JSON.parse(content), [row, second]);
assert.equal(await writeDatasetFile(handle, [second], features), 2);
assert.equal(writeCount, 1);
content = '{broken';
await assert.rejects(writeDatasetFile(handle, [second], features), /JSON tidak valid/);
assert.equal(content, '{broken');
content = JSON.stringify([{ ...row, extra: true }]);
await assert.rejects(writeDatasetFile(handle, [second], features), /60 fitur/);
permission = 'prompt';
await assert.rejects(writeDatasetFile(handle, [second], features), /Izin menulis/);
assert.equal(writeCount, 1);
assert.equal(mergeDatasetRows([], [row, { ...row }], features).length, 1);
console.log('PASS: 60-feature file merge, retained old rows, dedup, null, denied permission, corrupt/schema-invalid file preserved.');
