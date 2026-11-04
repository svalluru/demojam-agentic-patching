# Running the console on OpenShift

Builds the image and deploys the console as one pod, one container, with
`.env` as the only source of configuration.

```bash
./console-app-ocp-setup/deploy.sh                 # build, configure, deploy
./console-app-ocp-setup/deploy.sh --config-only   # after editing .env — no rebuild
./console-app-ocp-setup/deploy.sh --external      # keep .env's Route URLs for RAG/risk
./console-app-ocp-setup/deploy.sh --delete        # remove everything it creates
```

It prints the Route when it finishes. Requires `oc login` to the cluster named
by `OCP_API_URL` — it refuses to deploy anywhere else — and a namespace
(`NAMESPACE`) that already has Milvus, Llama Stack and the risk model — `rag-setup/` and
`risk_score/openshift/` deploy those, and this checks for them.

## Shape

```
Route (edge TLS, 1200s) ──▶ Service :8788 ──▶ pod
                                               └─ console  agentic-patching.py  :8788
                                                           page · /api/* · /lightwell/
```

One process, the same one `demo.sh` runs. There used to be a second
container serving the page and proxying `/api/*` to a backend bound to
127.0.0.1. That looked like it kept the API private, but the proxy forwarded
every route, approval included, so it protected nothing and cost a port, a
process and a proxy timeout. The API has no authentication either way — see
*Not covered here*.

| | |
|---|---|
| `Containerfile` | UBI9 python-311. No `pip install` — the app is standard library only |
| `manifests/deployment.yaml` | the container, probes, resources, volume |
| `manifests/service-route-pvc.yaml` | Service, Route, and a 1Gi PVC for `runs/` and `reports/` |

## Configuration

`deploy.sh` reads `.env` and splits it, so there is no second copy to keep
in step. Four keys go to a Secret by an explicit allowlist:

```
LIGHTSPEED_CLIENT_SECRET   AO_PASSWORD   AAP_TOKEN   VLLM_API_TOKEN
```

Everything else goes to a ConfigMap. The list is written out rather than
inferred, because classifying by guesswork is how a credential ends up
readable in a ConfigMap.

Two values are rewritten for in-cluster use, since going out to the router
and back to reach a pod in the same namespace costs a TLS handshake and
fails when the Route is down while the Service is fine:

```
LLAMA_STACK_URL  →  http://llamastack:8321
RISK_URL         →  http://risk-score:8080/v1/models/risk-score:predict
```

`--external` keeps whatever `.env` says.

One more is set regardless: `CONSOLE_HOST=0.0.0.0`, because the default of
`127.0.0.1` answers nothing from a Service.

## After changing .env

```bash
./console-app-ocp-setup/deploy.sh --config-only
```

Applies the ConfigMap and Secret and restarts the pod. A restart is the
point: config changes do not reach a running process on their own, and a pod
holding last week's `VECTOR_DB_ID` looks healthy while returning no RAG hits
at all.

**This clears any assessment open in a browser.** The run lives in the
backend's memory, so the page will say the console restarted and ask for a
fresh Assess. Do not redeploy mid-demo.

## Timeouts, which have to widen outward

```
AO_DECIDE_WAIT   900    the console waiting for an approved chain
Route           1200s   haproxy
```

The browser holds one connection for the whole of a decision. If any inner
value exceeds an outer one, the request is cut at the moment the work
finishes — which is what happened when the Route was annotated at exactly
900s.

## Things that bit us

**`dockerfilePath` is not optional.** The whole repo is uploaded as build
context so the Containerfile can COPY the sources, but the docker strategy
then looks for `./Dockerfile` at the root of it and fails naming a path that
was never going to exist.

**A build failure must stop the deploy.** An earlier version suppressed the
build output and fell back silently, so it reported success after a failed
build and the pod sat in ImagePullBackOff pulling a tag that had never been
pushed.

**`httpGet` probes do not work against a `127.0.0.1` bind.** The kubelet
probes the pod IP. The old backend container bound 127.0.0.1 and needed
`exec` probes; the console now binds 0.0.0.0, so plain `httpGet /healthz`
works. Keep `CONSOLE_HOST=0.0.0.0` or the probes fail again.

**`Recreate`, not `RollingUpdate`.** The pod writes to one RWO volume;
a rolling update would need two pods holding it at once, and the new one
stays Pending forever.

## Not covered here

The console has **no authentication**. The Route is reachable by anyone who
has the URL, and it can patch real machines. That is acceptable in a lab and
not much else; drop the Route and use `oc port-forward` if that matters.

Milvus, Llama Stack and the risk model are `rag-setup/deploy.sh` and
`risk_score/openshift/`. `setup.sh` orchestrates those; this assumes they are
already running.
