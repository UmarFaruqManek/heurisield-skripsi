/* Evaluate the exact numeric XGBoost trees exported from the trained booster. */
export function predictProbability(model, features) {
  if (model?.objective !== "binary:logistic" || model.feature_names?.length !== 17) {
    throw new Error("Unsupported URL model");
  }
  let margin = model.base_margin;
  for (const tree of model.trees) {
    let node = 0;
    while (tree.left[node] !== -1) {
      const raw = features[model.feature_names[tree.feature[node]]];
      // Number(null) is zero in JavaScript; null/undefined must instead follow
      // XGBoost's learned missing-value branch, exactly like Python np.nan.
      const missing = raw === null || raw === undefined || raw === "" || !Number.isFinite(Number(raw));
      const value = missing ? NaN : Number(raw);
      node = missing
        ? (tree.default_left[node] ? tree.left[node] : tree.right[node])
        : (value < tree.threshold_or_leaf[node] ? tree.left[node] : tree.right[node]);
    }
    margin += tree.threshold_or_leaf[node];
  }
  return margin >= 0 ? 1 / (1 + Math.exp(-margin)) : Math.exp(margin) / (1 + Math.exp(margin));
}
