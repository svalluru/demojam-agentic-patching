"""
Standalone local server for the risk-score model (no KServe).
Use this to test locally when KServe is not installed (e.g. Python 3.13).

  pip install -r requirements-local.txt
  python run_local.py

Then: curl -X POST http://localhost:8080/v1/models/risk-score:predict \
  -H "Content-Type: application/json" \
  -d '{"instances":[{"cvss":2.6,"age_days":100,"affected_hosts":10,"type":"security",
                     "cve_id":"CVE-2026-0001","host":"node1"}]}'

Each request is logged: the CVE and instance count, then one line per host with its inputs and the score sent back.
cve_id and host are optional and not model features; the agentic patching console sends them.
"""
import logging
import os
import time
import joblib
from fastapi import FastAPI, HTTPException
from uvicorn import run

app = FastAPI()
MODEL_DIR = "/mnt/models"
logger = logging.getLogger("risk-score")   # the name shown on each pod log line
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


FEATURES = ["cvss", "age_days", "affected_hosts", "type"]


def _ids(instances: list) -> tuple[str, list[str]]:
    """The CVE and per-instance host the console sends alongside the features (not model inputs), '-' when absent."""
    cves = sorted({str(i.get("cve_id") or "") for i in instances if isinstance(i, dict)} - {""})
    hosts = [str(i.get("host") or "-") if isinstance(i, dict) else "-" for i in instances]
    return (", ".join(cves) or "-"), hosts


@app.post("/v1/models/risk-score:predict")
def predict(payload: dict):
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    import pandas as pd
    started = time.monotonic()
    instances = payload.get("instances", payload.get("inputs", []))
    if not isinstance(instances, list):
        instances = [instances]
    cve, hosts = _ids(instances)
    df = pd.DataFrame(instances)
    for col in FEATURES:
        if col not in df.columns:
            logger.warning("risk request  cve=%s  instances=%d  REJECTED: missing column %s", cve, len(instances), col)
            raise HTTPException(status_code=400, detail=f"Missing column: {col}")
    pred = _pipeline.predict(df[FEATURES])
    pred = [max(0.0, min(100.0, float(p))) for p in pred]
    # What came in and what goes back, for the pod log: one line for the request, one per host.
    logger.info("risk request  cve=%s  instances=%d  (%d ms)", cve, len(instances),
                round((time.monotonic() - started) * 1000))
    for host, (_, row), score in zip(hosts, df[FEATURES].iterrows(), pred):
        logger.info("  %s  cvss=%s age_days=%s affected_hosts=%s type=%s  ->  risk %.1f",
                    host, row["cvss"], row["age_days"], row["affected_hosts"], row["type"], score)
    return {"predictions": pred}


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _pipeline is not None}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run(app, host="0.0.0.0", port=8080)
