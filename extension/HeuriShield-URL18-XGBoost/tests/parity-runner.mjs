import fs from "node:fs";
import { extractUrl18Features, ageLookupDomain } from "../src/analyzer/url/url18-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";

const source = JSON.parse(fs.readFileSync(0, "utf8"));
const main = JSON.parse(fs.readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const rows = source.map(item => {
  const features = extractUrl18Features(item.url);
  if (item.age !== null) features.domain_age_days = item.age;
  return { features, domain: ageLookupDomain(item.url),
    probability: predictProbability(main, features) };
});
process.stdout.write(JSON.stringify(rows));
