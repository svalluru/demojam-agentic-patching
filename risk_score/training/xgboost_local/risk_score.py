import time
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_absolute_error, r2_score

from xgboost import XGBRegressor

# -----------------------------
# A) Load training data from data.csv
# Columns: cvss, age_days, affected_hosts, type, risk_score
# -----------------------------
df = pd.read_csv("data.csv")

# -----------------------------
# B) Train XGBoost regressor
# -----------------------------
X = df[["cvss", "age_days", "affected_hosts", "type"]]
y = df["risk_score"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

preprocess = ColumnTransformer(
    transformers=[
        ("type_ohe", OneHotEncoder(handle_unknown="ignore"), ["type"]),
    ],
    remainder="passthrough"  # keep numeric columns as-is
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

pipeline = Pipeline(steps=[
    ("prep", preprocess),
    ("xgb", model),
])

pipeline.fit(X_train, y_train)

pred = pipeline.predict(X_test)
mae = mean_absolute_error(y_test, pred)
r2 = r2_score(y_test, pred)

print(f"MAE: {mae:.2f}   R^2: {r2:.3f}")

# -----------------------------
# C) Use it to score new errata
# -----------------------------
new_errata = pd.DataFrame([{
    "cvss": 2.6,
    "age_days": 10,
    "affected_hosts": 10,
    "type": "security"
}])

t0 = time.time()
pred_risk = float(pipeline.predict(new_errata)[0])
t1 = time.time()
print(f"Prediction took {t1 - t0:.3f} seconds")
pred_risk = max(0.0, min(100.0, pred_risk))  # clamp

print(f"Predicted risk_score: {pred_risk:.1f}")

# Your deterministic gate (Step 4)
auto_approve = pred_risk < 30.0
print("Decision:", "auto_approve" if auto_approve else "review")