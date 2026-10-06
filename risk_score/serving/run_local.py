"""
Standalone local server for the risk-score model (no KServe).
Use this to test locally when KServe is not installed (e.g. Python 3.13).

  pip install -r requirements-local.txt
  python run_local.py

Then: curl -X POST http://localhost:8080/v1/models/risk-score:predict \
  -H "Content-Type: application/json" \
  -d '{"instances":[{"cvss":2.6,"age_days":100,"affected_hosts":10,"type":"security"}]}'
"""
import logging
import os
import joblib
from fastapi import FastAPI, HTTPException
from uvicorn import run

app = FastAPI()
MODEL_DIR = "/mnt/models"
logger = logging.getLogger(__name__)
_pipeline = None


def _load_model():
    global _pipeline
    candidates = [
        os.path.join(MODEL_DIR, "model.joblib"),
        os.path.join(MODEL_DIR, "model"),
        "model.joblib",
        os.path.join(os.path.dirname(__file__), "model.joblib"),
        os.path.join(os.path.dirname(__file__), "..", "training", "model.joblib"),
    ]
    for p in candidates:
        p = os.path.abspath(p)
        if os.path.isfile(p):
            _pipeline = joblib.load(p)
            logger.info("Loaded model from %s", p)
            return
    raise FileNotFoundError(f"No model.joblib found. Tried: {candidates}")


@app.on_event("startup")
def startup():
    _load_model()


@app.post("/v1/models/risk-score:predict")
def predict(payload: dict):
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    import pandas as pd
    instances = payload.get("instances", payload.get("inputs", []))
    if not isinstance(instances, list):
        instances = [instances]
    df = pd.DataFrame(instances)
    for col in ["cvss", "age_days", "affected_hosts", "type"]:
        if col not in df.columns:
            raise HTTPException(status_code=400, detail=f"Missing column: {col}")
    pred = _pipeline.predict(df[["cvss", "age_days", "affected_hosts", "type"]])
    pred = [max(0.0, min(100.0, float(p))) for p in pred]
    return {"predictions": pred}


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _pipeline is not None}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run(app, host="0.0.0.0", port=8080)
