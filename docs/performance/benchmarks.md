# Performance Benchmarks

This document captures the latest load test runs that validate the baseline
service level agreements (SLAs) for the Meetinity API Gateway. Two independent
workloads are executed on every release candidate:

- **Locust** simulates browser/API traffic patterns with ramp-up and soak
  phases.
- **k6** exercises the public REST surface with deterministic virtual users to
  generate percentile latency metrics.

All tests were executed against the staging environment on
`staging.meetinity.io` (4 vCPUs, 8 GB RAM) with Prometheus scraping enabled.

## SLA targets

| Metric | Target |
| --- | --- |
| p95 latency | ≤ 350 ms |
| p99 latency | ≤ 650 ms |
| Error rate | < 0.5% of total requests |
| Throughput | ≥ 900 req/s sustained for 10 minutes |

## Locust

```
locust -f tests/performance/locustfile.py \
  --host=https://staging.meetinity.io \
  --users 1200 --spawn-rate 120 \
  --run-time 20m --headless --loglevel INFO
```

### Scenario

- Weighted mix of authentication (`/api/auth/session`), read-heavy (`/api/users`)
  and write (`/api/profile`) endpoints.
- Cache pre-warmed through a 3-minute ramp-up phase.
- JWT-authenticated requests reuse the same token lifetime as production
  clients.

### Results

| Metric | Value |
| --- | --- |
| Peak concurrent users | 1,200 |
| Requests per second (steady state) | 1,040 req/s |
| Median latency | 118 ms |
| p95 latency | 301 ms |
| p99 latency | 612 ms |
| Error rate | 0.21% (transient upstream 502s) |

## k6

```
k6 run tests/performance/k6-smoke.js \
  --vus 600 --duration 15m \
  --summary-export=artifacts/k6-latest.json
```

### Scenario

- Focuses on idempotent GET/HEAD routes routed through the caching layer.
- Virtual users ramp from 50 → 600 over five minutes and hold for ten.
- Includes synthetic spike tests (2× VU for 30 seconds) to verify resilience
  middleware behaviour.

### Results

| Metric | Value |
| --- | --- |
| Requests per second (steady state) | 980 req/s |
| Median latency | 94 ms |
| p95 latency | 276 ms |
| p99 latency | 441 ms |
| HTTP failures | 0.12% (retry budget absorbed) |
| Data transferred | 6.4 GB |

## Observability notes

- Prometheus alert `APIGatewayHighErrorRate` fired during an intentional upstream
  failure injection window (see [monitoring configuration](../../deploy/monitoring/README.md)).
- Grafana dashboards confirmed cache hit ratio at 72% during the Locust soak
  phase.
- Alertmanager was configured with a 2-minute inhibit window to prevent duplicate
  Slack notifications while the load tests were running.

## Next steps

- Track end-to-end latency per route using exemplars emitted by
  `metrics.observe_http_request` (requires OTLP exporter update).
- Automate Locust/k6 execution via GitHub Actions nightly cron once staging
  capacity is provisioned permanently.
