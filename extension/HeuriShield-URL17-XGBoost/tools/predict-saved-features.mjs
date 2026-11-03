import fs from "node:fs";
import { predictProbability } from "../src/model/xgboost-engine.js";
const model = JSON.parse(fs.readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const values = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(values.map(features => predictProbability(model, features))));
