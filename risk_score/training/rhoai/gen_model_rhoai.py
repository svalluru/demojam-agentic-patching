import json
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score

# Encode categorical feature manually
TYPE_MAP = {
    "security": 0,
    "bugfix": 1,
    "enhancement": 2,
}

# Load your dataset
df = pd.read_csv("data.csv")

required_cols = ["cvss", "age_days", "affected_hosts", "type", "risk_score"]
missing = [c for c in required_cols if c not in df.columns]
if missing:
    raise ValueError(f"Missing required columns: {missing}")

# Convert type -> numeric
df["type_encoded"] = df["type"].map(TYPE_MAP)

if df["type_encoded"].isna().any():
    bad = sorted(df.loc[df["type_encoded"].isna(), "type"].dropna().unique())
    raise ValueError(f"Unknown type values found: {bad}")

# Feature order matters for v2 infer endpoint
feature_names = ["cvss", "age_days", "affected_hosts", "type_encoded"]

X = df[feature_names].astype("float32")
y = df["risk_score"].astype("float32")

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Convert to DMatrix
dtrain = xgb.DMatrix(data=X_train, label=y_train, feature_names=feature_names)
dtest = xgb.DMatrix(data=X_test, label=y_test, feature_names=feature_names)

# Regression parameters
params = {
    "max_depth": 5,
    "eta": 0.05,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "lambda": 1.0,
    "objective": "reg:squarederror",
    "eval_metric": "rmse",
    "seed": 42,
}

num_round = 400

# Train native Booster
bst = xgb.train(
    params=params,
    dtrain=dtrain,
    num_boost_round=num_round,
    evals=[(dtrain, "train"), (dtest, "test")],
    verbose_eval=False,
)

# Evaluate
preds = bst.predict(dtest)
mae = mean_absolute_error(y_test, preds)
r2 = r2_score(y_test, preds)

print("MAE:", round(mae, 4))
print("R2 :", round(r2, 4))

# Save native model for RHOAI / MLServer
model_file_name = "model.json"
bst.save_model(model_file_name)
print(f"Saved model to {model_file_name}")

# Save schema for inference clients
schema = {
    "feature_order": feature_names,
    "type_mapping": TYPE_MAP,
    "example_v2_request": {
        "inputs": [
            {
                "name": "input-0",
                "shape": [1, 4],
                "datatype": "FP32",
                "data": [2.6, 100.0, 10.0, 0.0]
            }
        ]
    }
}

with open("schema.json", "w") as f:
    json.dump(schema, f, indent=2)

print("Saved schema.json")