"""
Train the risk-score pipeline and save it for deployment (e.g. OpenShift AI).
Run from training/: python save_model.py
Output: model.joblib (upload to S3 or PVC for serving).
"""
import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from xgboost import XGBRegressor

df = pd.read_csv("data.csv")
X = df[["cvss", "age_days", "affected_hosts", "type"]]
y = df["risk_score"]

preprocess = ColumnTransformer(
    transformers=[
        ("type_ohe", OneHotEncoder(handle_unknown="ignore"), ["type"]),
    ],
    remainder="passthrough",
)
model = XGBRegressor(
    n_estimators=400,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    reg_lambda=1.0,
    random_state=42,
)
pipeline = Pipeline(steps=[("prep", preprocess), ("xgb", model)])
pipeline.fit(X, y)

joblib.dump(pipeline, "model.joblib")
print("Saved pipeline to model.joblib. Upload this file to S3 or PVC for serving.")
