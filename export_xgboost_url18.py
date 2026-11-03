"""Export the frozen URL-only XGBoost booster to a browser-readable JSON file."""

import json
import math
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parent
MODEL = ROOT / "hasil_perbandingan_6_model/model/XGBoost.joblib"
CONFIG = ROOT / "hasil_perbandingan_6_model/evaluasi_model.json"
OUT = ROOT / "HeuriShield-URL18-XGBoost/src/model/xgboost-url18.json"


def export(model, feature_names, threshold, destination):
    raw = json.loads(model.get_booster().save_raw(raw_format="json"))
    learner = raw["learner"]
    booster = learner["gradient_booster"]["model"]
    base = float(json.loads(learner["learner_model_param"]["base_score"])[0])
    if learner["objective"]["name"] != "binary:logistic" or model.n_features_in_ != len(feature_names):
        raise ValueError("Model feature contract mismatch")
    trees = []
    for tree in booster["trees"]:
        if any(int(kind) != 0 for kind in tree["split_type"]):
            raise ValueError("Categorical splits need another browser evaluator")
        trees.append({
            "left": tree["left_children"],
            "right": tree["right_children"],
            "default_left": tree["default_left"],
            "feature": tree["split_indices"],
            "threshold_or_leaf": tree["split_conditions"],
        })
    result = {
        "model_family": "XGBoost", "objective": "binary:logistic",
        "feature_names": feature_names,
        "threshold": threshold,
        "base_margin": math.log(base / (1 - base)),
        "trees": trees,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
    print(f"Exported {len(trees)} trees, {len(feature_names)} features to {destination}")


def main():
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    export(joblib.load(MODEL), config["feature_names"],
           config["models"]["XGBoost"]["validation"]["threshold"], OUT)


if __name__ == "__main__":
    main()
