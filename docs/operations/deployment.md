# Deployment Operations Guide

This guide explains how to deploy the Meetinity API Gateway safely across multiple environments with zero downtime.

## Configuration strategy

The gateway loads configuration from layered `.env` files and the process environment. Files are resolved in the following order (later files override earlier ones):

1. `.env`
2. `.env.local`
3. `.env.<environment>` (for example `.env.production`)
4. `.env.<environment>.local`

Hierarchical variables using double underscores (for example `PROXY__TIMEOUT__READ=10`) are supported. They are flattened to their uppercase underscore equivalents (`PROXY_TIMEOUT_READ`) and exposed through `app.config` as well as the `HIERARCHICAL_CONFIG` tree. This allows Ops teams to group related settings without losing compatibility with existing configuration keys.

Sensitive values such as secrets, API keys, and tokens are automatically redacted from the structured configuration snapshot emitted on startup.

## Runtime profiles

The runtime can be tailored per environment via the following knobs:

- **Connection pooling** – `PROXY_POOL_CONNECTIONS`, `PROXY_POOL_MAXSIZE`, and `PROXY_POOL_BLOCK` (default: enabled) control upstream HTTP pooling.
- **Streaming proxy** – `PROXY_STREAM_UPSTREAM` and `PROXY_STREAM_CHUNK_SIZE` stream large upstream payloads directly to clients when caching and transformation pipelines are disabled. This reduces peak memory usage per request.
- **Cache tuning** – `CACHE_ENABLED`, `CACHE_DEFAULT_TTL`, `CACHE_VARY_HEADERS`.
- **Gunicorn/WSGI** – `WSGI_WORKERS`, `WSGI_THREADS`, `WSGI_GRACEFUL_TIMEOUT`, and `WSGI_MAX_REQUESTS` integrate with the production Docker image.

The application logs a sanitized configuration snapshot containing these parameters during startup.

## Docker-based deployments

A production-ready multi-stage Dockerfile is provided at the repository root. It builds dependencies in an isolated virtual environment before copying only the runtime artefacts to the final image.

```bash
# Build and tag
 docker build -t ghcr.io/meetinity/api-gateway:latest .

# Run locally with production defaults
 docker compose -f deploy/docker-compose.yml up --build
```

The Compose file in `deploy/docker-compose.yml` uses the production image and enables rolling updates via `start-first` update semantics. Adjust the `env_file` entries to match your environment.

## Kubernetes deployment manifests

The `deploy/k8s/` directory contains manifests optimised for horizontal scalability:

- `configmap.yaml` – layered configuration with hierarchical keys.
- `deployment.yaml` – baseline deployment (`-blue`) with readiness/liveness probes, pre-stop delay, and resource requests.
- `service.yaml` – stable service pointing to the active colour (`blue` by default).
- `hpa.yaml` – autoscaling policy targeting 65% CPU and 70% memory utilisation.

Apply the manifests in the following order:

```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
```

### Zero-downtime strategies

Two automation scripts in `scripts/` orchestrate zero-downtime upgrades.

#### Blue/green deployments

```bash
scripts/deploy_blue_green.sh ghcr.io/meetinity/api-gateway:2024.05.01 production
```

The script will:

1. Apply the latest configuration ConfigMap.
2. Determine the currently active colour from the service annotation `gateway.meetinity.io/active-color`.
3. Materialise a new deployment (`-blue` or `-green`) from `deploy/k8s/deployment.yaml`, overriding the image reference and colour labels.
4. Wait for the new deployment to become ready and update the service selector and HPA target.
5. Scale down the previously active colour to zero replicas.

This workflow achieves zero downtime by keeping both colours available until the service selector flips.

#### Rolling updates

```bash
scripts/deploy_rolling.sh ghcr.io/meetinity/api-gateway:2024.05.01 staging
```

The rolling deployment script updates the image on the existing deployment (default `meetinity-api-gateway-blue`) and waits for the rollout to finish. It annotates the deployment with a UTC timestamp to simplify audit trails. Rolling updates honour the `maxUnavailable=0 / maxSurge=1` policy defined in the manifest.

### Horizontal scaling considerations

- Ensure the `HorizontalPodAutoscaler` references the active deployment name (the blue/green script patches it automatically).
- Keep `terminationGracePeriodSeconds` aligned with Gunicorn’s graceful timeout to allow in-flight requests to finish before pods terminate.
- For environments with aggressive autoscaling, consider increasing `WSGI_WORKERS` and `PROXY_POOL_MAXSIZE` to match expected concurrency.

## Checklist

1. Commit configuration updates (`deploy/k8s/configmap.yaml`) alongside code changes.
2. Build and push a new container image.
3. For production, prefer the blue/green workflow; for pre-production, rolling updates are usually sufficient.
4. Monitor the `/metrics` endpoint or Prometheus scrape job to validate request latency, upstream failure rate, and cache hit rate during the rollout.
