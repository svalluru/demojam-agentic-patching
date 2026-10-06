# KServe custom predictor for XGBoost risk-score pipeline
FROM python:3.11-slim

WORKDIR /opt/app
COPY requirements.txt .

# Install build deps for psutil (kserve dependency); remove after pip to keep image small
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y gcc python3-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY model.py .

# KServe expects port 8080
ENV PORT=8080
EXPOSE 8080

# Default: run the model server (model name and storage are set by OpenShift AI / KServe)
CMD ["python", "model.py", "--model_name=risk-score", "--http_port=8080"]
