# Host XGBoost risk-score model on Red Hat OpenShift AI

**Note:** vLLM is for **LLM inference only**. XGBoost is served on OpenShift AI using **KServe** with a **custom predictor** container, not vLLM.

## Two deployment paths

| Path | Requires | When to use |
|------|----------|-------------|
| **A — OpenShift AI / KServe** (Steps 1–6 below) | RHOAI operator, model serving enabled, S3 or PVC | You already run RHOAI and want model registry, metrics, and autoscaling |
| **B — [Plain OpenShift app](#part-b--deploy-as-a-plain-openshift-application-no-rhoai) (Part B)** | Only `oc` and a namespace | No RHOAI on the cluster, or you want the smallest possible footprint |

Both expose the identical API (`POST /v1/models/risk-score:predict`), so the console's `RISK_URL` works against either without code changes.

---

## Overview

1. Train and save the pipeline as `model.joblib`.
2. Upload `model.joblib` to object storage (S3) or a PVC.
3. Build a custom predictor image that loads the model and serves predictions.
4. Add a custom Serving Runtime (or use a custom InferenceService) and deploy the model.

---

## Prerequisites

- Red Hat OpenShift AI installed with **model serving** enabled (KServe).
- OpenShift CLI (`oc`) and cluster access.
- A **Data Science Project** (or namespace) where you can deploy models.
- Object storage (S3-compatible) or PVC for the model artifact.

---

## Step 1: Train and save the model

From the `training/` directory:

```bash
cd training
pip install pandas scikit-learn xgboost joblib
python save_model.py
```

This creates **`model.joblib`** in `training/`. Keep this file for the next step.

### Run the predictor locally (optional)

To test the server without KServe/OpenShift (e.g. Python 3.13, or to avoid rebuilding the image for every fix), use the standalone local server (no KServe dependency):

```bash
# From repo root (cox/)
cd serving
pip install -r requirements-local.txt
python run_local.py
```

Model is loaded from `../training/model.joblib`. In another terminal:

```bash
curl -s -X POST http://localhost:8080/v1/models/risk-score:predict \
  -H "Content-Type: application/json" \
  -d '{"instances":[{"cvss":2.6,"age_days":100,"affected_hosts":10,"type":"security"}]}'
```

Expected: `{"predictions":[...]}`. Once this works, rebuild the image and push.

**Alternative (KServe):** If you use Python 3.9–3.12 and have KServe installed, you can run `pip install -r requirements.txt` and `python model.py --model_name=risk-score --http_port=8080` instead.

---

## Step 2: Upload the model to storage

OpenShift AI needs the model at a URI it can mount or download.

**Option A – S3-compatible object storage**

1. Create a bucket and upload `model.joblib`.
2. Note the URI, e.g. `s3://my-bucket/risk-score/model.joblib`.
3. In OpenShift AI, create a **data connection** (Settings → Data connections) with the S3 bucket credentials and bucket/prefix so the platform can resolve that URI.

**Option B – PVC**

1. Create a PVC in your project and copy `model.joblib` into it (e.g. via a Pod or `oc rsync`).
2. Note the path, e.g. `pvc://my-pvc/model.joblib`.

---

## Step 3: Build and push the custom predictor image

The predictor is the Python server that loads `model.joblib` and exposes a REST API. Build and push an image to a registry OpenShift can pull from (e.g. OpenShift internal registry or Quay).

**Important:** If you build on Apple Silicon (M1/M2/M3) and your OpenShift nodes are x86_64 (typical), you must build for `linux/amd64` or you will get `Exec format error` when the pod runs:

```bash
cd serving
docker build --platform linux/amd64 -t <your-registry>/risk-score-predictor:latest .
docker push <your-registry>/risk-score-predictor:latest
```

If your cluster is ARM64 (e.g. Graviton), use `--platform linux/arm64` instead. If you are on an x86_64 build machine, you can omit `--platform`.

If using the OpenShift internal registry:

```bash
oc whoami -t | docker login -u <user> --password-stdin <registry-url>
# Then build with that registry in the image tag and push
```

---

## Step 4: Add a custom Serving Runtime (OpenShift AI UI)

1. Log in to **OpenShift AI** as a user who can manage **Serving runtimes** (e.g. admin).
2. Go to **Settings** → **Serving runtimes**.
3. Click **Add serving runtime** → choose **Single-model serving platform** (or the option that matches your cluster).
4. **Start from scratch** and paste a YAML like the one below. Replace `<your-registry>/risk-score-predictor:latest` with your image.

```yaml
apiVersion: serving.kserve.io/v1alpha1
kind: ServingRuntime
metadata:
  name: xgboost-risk-score-runtime
  annotations:
    openshift.io/display-name: "XGBoost risk-score (custom)"
spec:
  supportedModelFormats:
    - name: custom
      version: "1"
      autoSelect: true
  protocolVersions:
    - v1
  multiModel: false
  grpcEndpoint: "port:8081"
  containers:
    - name: kserve-container
      image: <your-registry>/risk-score-predictor:latest
      imagePullPolicy: Always   # always pull when using :latest so updates are picked up
      command: ["python", "model.py"]
      args:
        - --model_name=risk-score
        - --http_port=8080
      resources:
        requests:
          cpu: "100m"
          memory: 256Mi
        limits:
          cpu: "2"
          memory: 2Gi
  builtInAdapter:
    serverType: custom
```

5. Save. The new runtime (e.g. "XGBoost risk-score (custom)") will appear in the list.

**Tip:** If you use the `:latest` tag and push an updated image, add `imagePullPolicy: Always` to the container spec (as in the YAML above) so new pods pull the new image. Then delete the model pod to force a fresh pull:

```bash
# Replace <project> and <pod-name> with your Data Science project and the risk-score predictor pod name
oc get pods -n <project> -l serving.kserve.io/inferenceservice=risk-score
oc delete pod -n <project> <pod-name>
```

---

## Step 5: Deploy the model in OpenShift AI

1. Open your **Data Science Project**.
2. In **Models and model servers**, **Configure server** (if needed) and ensure a model server is created.
3. Click **Deploy model**.
4. Choose:
   - **Model name:** e.g. `risk-score`.
   - **Serving runtime:** the one you added (e.g. "XGBoost risk-score (custom)").
   - **Model location:** the URI from Step 2 (S3 or PVC), e.g. `s3://my-bucket/risk-score/model.joblib` or `pvc://my-pvc/model.joblib`.
5. Deploy. OpenShift AI will create an InferenceService that uses your image and mounts/downloads the model to `/mnt/models` so the predictor can load `model.joblib`.

---

## Step 6: Call the inference endpoint

After the deployment is **Ready**, use the route URL shown in the UI (or get it via `oc get ksvc` / the dashboard).

**Request (v1-style):**

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "instances": [
      {
        "cvss": 2.6,
        "age_days": 100,
        "affected_hosts": 10,
        "type": "security"
      }
    ]
  }' \
  "https://<inference-service-url>/v1/models/risk-score:predict"
```

**Example response:**

```json
{ "predictions": [ 42.3 ] }
```

Use the returned score (0–100) in your workflow (e.g. auto-approve if &lt; 30, else review).

---

## Alternative: Deploy via InferenceService YAML (CLI)

If you prefer not to use the UI, create an InferenceService that uses your image and storage URI:

```yaml
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: risk-score
  namespace: <your-ds-project>
spec:
  predictor:
    containers:
      - name: kserve-container
        image: <your-registry>/risk-score-predictor:latest
        imagePullPolicy: Always
        command: ["python", "model.py"]
        args:
          - --model_name=risk-score
          - --http_port=8080
        env:
          - name: STORAGE_URI
            value: "s3://my-bucket/risk-score/model.joblib"
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: "2"
            memory: 2Gi
```

Apply with:

```bash
oc apply -f inference-service.yaml
```

Then get the URL and call `/v1/models/risk-score:predict` as above.

---

## Summary

| Item | What to use |
|------|----------------------|
| **Runtime** | KServe custom predictor (not vLLM) |
| **Model artifact** | `model.joblib` from `training/save_model.py` |
| **Storage** | S3 or PVC URI |
| **Image** | `serving/Dockerfile` + `serving/model.py` |
| **API** | POST `.../v1/models/risk-score:predict` with `{"instances": [{...}]}` |

vLLM remains for LLM workloads; XGBoost is served via this custom KServe predictor on OpenShift AI.

---
---

# Part B — Deploy as a plain OpenShift application (no RHOAI)

This path drops KServe, ServingRuntimes, InferenceServices, S3 data connections, and the RHOAI operator entirely. What you get instead is an ordinary `Deployment` + `Service` + optional `Route` running a FastAPI server — the same three objects as any other app in the namespace.

Two things make this simple:

- **`serving/run_local.py` already has no KServe dependency.** It is a plain FastAPI app that serves `POST /v1/models/risk-score:predict` and `GET /health`. It is the server, not a test harness — Part B just containerizes it.
- **The model is baked into the image.** `model.joblib` is a few hundred KB, so there is no reason to mount a PVC or pull from S3 at startup. The image is self-contained and the pod has no storage dependency.

### Trade-offs versus Part A

You give up model-registry integration, per-model metrics, canary rollout, and scale-to-zero. You gain a deployment with no operator dependency that starts in seconds and can be redeployed by anyone with `edit` on the namespace. Retraining means rebuilding the image rather than swapping an S3 object — fine at this model's release cadence, annoying if you retrain daily.

---

## Step B1: Train and save the model

Identical to Step 1. From the repo root:

```bash
cd risk_score/training
pip install pandas scikit-learn xgboost joblib
python save_model.py
```

Confirm the artifact exists — the image build will fail without it:

```bash
ls -la model.joblib
```

---

## Step B2: Create the deployment Dockerfile

This differs from `serving/Dockerfile` in three ways: it has no `kserve` dependency, runs `run_local.py` instead of `model.py`, and copies the model into the image.

Both files already exist in the repo — **`risk_score/Dockerfile`** and **`risk_score/serving/requirements-ocp.txt`**. The Dockerfile sits at the `risk_score/` root, not inside `serving/`, so `oc new-build --binary` finds it without extra configuration.

```dockerfile
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
```

`run_local.py` searches several paths for the model and includes `model.joblib` relative to its own directory, so copying it to `/opt/app` alongside the script is enough — no `STORAGE_URI`, no `/mnt/models` mount.

### Why `xgboost-cpu` rather than `xgboost`

`requirements-ocp.txt` is identical to `requirements-local.txt` except for this one line. Plain `xgboost` 3.x pulls in `nvidia-nccl-cu12` — **469 MB of CUDA libraries** that CPU-only inference never loads. `xgboost-cpu` is the same project and the same `import xgboost` namespace, built without GPU support.

Measured on this model, cross-built for `linux/amd64`:

| | `xgboost` | `xgboost-cpu` |
|---|---|---|
| Image size | 1.23 GB | **523 MB** |
| `nvidia/` in site-packages | 469 MB | none |
| xgboost version | 3.2.0 | 3.2.0 |
| Predictions | — | bit-identical |

The local-development path in Step 1 still uses `requirements-local.txt` with plain `xgboost`; only the container image differs.

---

## Step B3: Build the image in the cluster

**Recommended — binary build.** OpenShift builds on a cluster node, so the image always matches the node architecture. This sidesteps the Apple Silicon `Exec format error` that Step 3 warns about, with no `--platform` flag to get wrong:

```bash
NAMESPACE=agentic-patching

oc new-build --name=risk-score --binary --strategy=docker -n "$NAMESPACE"

cd risk_score
oc start-build risk-score --from-dir=. --follow -n "$NAMESPACE"
```

This produces `image-registry.openshift-image-registry.svc:5000/$NAMESPACE/risk-score:latest` and an ImageStream the Deployment can reference directly.

**Alternative — build locally and push.** Only if you need the image in an external registry such as Quay. Match the cluster architecture explicitly:

```bash
cd risk_score
podman build --platform linux/amd64 -f Dockerfile -t quay.io/<org>/risk-score:latest .
podman push quay.io/<org>/risk-score:latest
```

---

## Step B4: Deploy Deployment + Service + Route

Create **`risk_score/openshift/risk-score.yaml`**. Adjust `namespace` if you are not using `agentic-patching`, and replace the image if you pushed to an external registry.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: risk-score
  namespace: agentic-patching
  labels:
    app: risk-score
    app.kubernetes.io/part-of: agentic-patching-console
spec:
  replicas: 1
  selector:
    matchLabels:
      app: risk-score
  template:
    metadata:
      labels:
        app: risk-score
    spec:
      containers:
        - name: risk-score
          image: image-registry.openshift-image-registry.svc:5000/agentic-patching/risk-score:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 30
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: "2"
              memory: 2Gi
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
---
apiVersion: v1
kind: Service
metadata:
  name: risk-score
  namespace: agentic-patching
  labels:
    app: risk-score
spec:
  selector:
    app: risk-score
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
# Optional. Only needed to reach the model from outside the cluster (manual
# testing). The console calls the Service directly and does not need this.
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: risk-score
  namespace: agentic-patching
spec:
  to:
    kind: Service
    name: risk-score
  port:
    targetPort: http
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

Apply and wait:

```bash
oc apply -f risk_score/openshift/risk-score.yaml
oc rollout status deployment/risk-score -n agentic-patching --timeout=180s
```

The readiness probe hits `/health`, which reports `model_loaded`. If the model failed to load, the pod never becomes ready rather than silently serving errors.

---

## Step B5: Verify the endpoint

In-cluster, which is how the console will reach it:

```bash
oc run curl-test --rm -it --restart=Never --image=curlimages/curl -n agentic-patching -- \
  curl -s -X POST http://risk-score:8080/v1/models/risk-score:predict \
  -H "Content-Type: application/json" \
  -d '{"instances":[{"cvss":9.8,"age_days":47,"affected_hosts":12,"type":"security"}]}'
```

Expected — a single score, clamped to 0–100:

```json
{ "predictions": [ 100.0 ] }
```

The endpoint also accepts a batch, which is how multiple affected hosts are scored:

```bash
-d '{"instances":[
      {"cvss":9.8,"age_days":5,"affected_hosts":3,"type":"security"},
      {"cvss":4.1,"age_days":200,"affected_hosts":40,"type":"security"}
    ]}'
# -> {"predictions":[93.56, 85.84]}
```

Note that the console calls this **once per host** rather than batching (see `_try_score_hosts` in `src/local/cve_flow_demo.py`), so expect N requests for N affected systems.

Via the Route, if you created one:

```bash
RISK_HOST=$(oc get route risk-score -n agentic-patching -o jsonpath='{.spec.host}')
curl -sk -X POST "https://${RISK_HOST}/v1/models/risk-score:predict" \
  -H "Content-Type: application/json" \
  -d '{"instances":[{"cvss":9.8,"age_days":47,"affected_hosts":12,"type":"security"}]}'
```

---

## Step B6: Point the console at the model

The console reads `RISK_URL` and calls it from `risk_score()` in `src/local/cve_flow.py`. Set it to the in-cluster Service URL:

```
RISK_URL=http://risk-score.agentic-patching.svc.cluster.local:8080/v1/models/risk-score:predict
```

Set it in whichever place matches how you run the console:

```bash
# Console running in-cluster
oc set env deployment/cve-console -n agentic-patching \
  RISK_URL=http://risk-score.agentic-patching.svc.cluster.local:8080/v1/models/risk-score:predict

# Console running locally against a port-forward
oc port-forward svc/risk-score 8080:8080 -n agentic-patching
# then in src/local/cve_console/.env:
#   RISK_URL=http://127.0.0.1:8080/v1/models/risk-score:predict
```

**No application code change is required.** `risk_score()` already sends `{"instances": [{"cvss":…, "age_days":…, "affected_hosts":…, "type":…}]}` and reads back the `predictions` key — exactly the contract `run_local.py` implements. The default `RISK_URL` shipped in `SETTINGS_DEFAULTS` is a `/v2/.../infer` placeholder that never matched; this replaces it with a real v1 endpoint.

### Confirm the model is actually being used

`risk_score()` catches every exception and silently falls back to an arithmetic heuristic, so a broken URL looks like a working one. After setting `RISK_URL`, verify that real scores are coming back rather than the heuristic:

```bash
oc logs -f deployment/risk-score -n agentic-patching
```

Start a patch run from the console. You should see a `POST /v1/models/risk-score:predict` access log line per affected host. **If no requests arrive, the console is still running the fallback heuristic** — the scores in the UI will be `(cvss * 6.0) + min(age_days/30, 10) + min(affected_hosts, 10)`, which crosses the review threshold of 30.0 at any CVSS above 5.0 and flags essentially every host for approval.

---

## Updating the model

Because the artifact is baked into the image, retraining means rebuild and roll:

```bash
cd risk_score/training && python save_model.py && cd ..
oc start-build risk-score --from-dir=. --follow -n agentic-patching
oc rollout restart deployment/risk-score -n agentic-patching
```

`imagePullPolicy: Always` plus `rollout restart` guarantees the new `:latest` is pulled. If you would rather retrain without rebuilding, mount a PVC at `/mnt/models` and drop `model.joblib` there — `run_local.py` checks that path first, ahead of the baked-in copy.

---

## Part B summary

| Item | What to use |
|------|-------------|
| **Runtime** | FastAPI + uvicorn in a plain Deployment — no KServe, no RHOAI operator |
| **Model artifact** | `training/model.joblib`, baked into the image at build time |
| **Storage** | None (optional PVC at `/mnt/models` to override the baked-in model) |
| **Image** | `risk_score/Dockerfile` + `serving/run_local.py` + `serving/requirements-ocp.txt` (523 MB) |
| **Objects** | `Deployment`, `Service`, optional `Route` |
| **API** | POST `/v1/models/risk-score:predict` with `{"instances": [{...}]}` — identical to Part A |
| **Console wiring** | `RISK_URL=http://risk-score.agentic-patching.svc.cluster.local:8080/v1/models/risk-score:predict` |
