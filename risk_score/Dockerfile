# Plain OpenShift deployment of the risk-score model — no KServe, no RHOAI.
# Build context must be risk_score/:
#   cd risk_score && oc start-build risk-score --from-dir=. --follow
FROM python:3.11-slim

WORKDIR /opt/app

# No kserve. Uses xgboost-cpu to avoid ~469 MB of unused CUDA libraries.
COPY serving/requirements-ocp.txt .
RUN pip install --no-cache-dir -r requirements-ocp.txt

COPY serving/run_local.py .
COPY training/model.joblib .

EXPOSE 8080

# OpenShift's restricted-v2 SCC assigns a random non-root UID; declaring one
# keeps runAsNonRoot: true valid on vanilla Kubernetes too.
USER 1001

CMD ["python", "run_local.py"]
