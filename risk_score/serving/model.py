"""
KServe custom predictor for the risk-score XGBoost pipeline.
Expects payload: {"instances": [{"cvss": float, "age_days": int, "affected_hosts": int, "type": str}, ...]}
Returns: {"predictions": [risk_score, ...]} (clamped 0–100).
Model artifact (model.joblib) is loaded from /mnt/models (KServe) or current dir / ../training (local).
"""
import argparse
import logging
import os
import joblib
import kserve
from kserve import Model, ModelServer

MODEL_DIR = "/mnt/models"
logger = logging.getLogger(__name__)


class RiskScoreModel(Model):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name
        self.ready = False
        self.load()

    def load(self):
        # Search order: KServe mount, then local paths for testing
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
                self._pipeline = joblib.load(p)
                self.ready = True
                logger.info("Loaded model from %s", p)
                return
        raise FileNotFoundError(f"No model.joblib found. Tried: {candidates}")

    def predict(
        self,
        payload: dict,
        headers: dict = None,
    ) -> dict:
        import pandas as pd
        instances = payload.get("instances", payload.get("inputs", []))
        if not isinstance(instances, list):
            instances = [instances]
        df = pd.DataFrame(instances)
        for col in ["cvss", "age_days", "affected_hosts", "type"]:
            if col not in df.columns:
                raise ValueError(f"Missing column: {col}")
        pred = self._pipeline.predict(df[["cvss", "age_days", "affected_hosts", "type"]])
        pred = [max(0.0, min(100.0, float(p))) for p in pred]
        return {"predictions": pred}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(parents=[kserve.model_server.parser])
    args, _ = parser.parse_known_args()
    # KServe version compatibility: configure_logging may not exist
    if getattr(args, "configure_logging", True):
        kserve_logging = getattr(kserve, "logging", None)
        if kserve_logging is not None and hasattr(kserve_logging, "configure_logging"):
            kserve_logging.configure_logging(getattr(args, "log_config_file", None))
    model = RiskScoreModel(args.model_name)
    ModelServer().start([model])
