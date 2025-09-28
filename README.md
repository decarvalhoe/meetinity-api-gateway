# Meetinity API Gateway

The Meetinity API Gateway is the single entry point for the Meetinity platform.
It terminates client connections, authenticates traffic, applies cross-cutting
policies (rate limiting, caching, observability) and proxies requests to the
appropriate backend microservices.

## Highlights

- **Flexible routing** – Dynamic service discovery, weighted load balancing and
  circuit-breaking middleware keep upstream traffic resilient.
- **Security first** – JWT enforcement, structured logging, and configurable
  CORS policies protect public endpoints.
- **Observability built-in** – Prometheus metrics, distributed tracing hooks and
  structured JSON logs enable end-to-end debugging.
- **Performance ready** – Response caching with single-flight deduplication and
  automated load tests (Locust/k6) guard latency SLAs.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app src.app run --debug
```

Key environment variables are documented in
[`docs/operations/deployment.md`](docs/operations/deployment.md) and cover rate
limits, upstream timeouts, caching, JWT secrets and OpenTelemetry exporters.

## Testing & quality gates

| Type | Command | Notes |
| --- | --- | --- |
| Unit / integration | `pytest` | Covers middleware, analytics, caching and service discovery. |
| Load (Locust) | `locust -f tests/performance/locustfile.py --host=<gateway>` | Simulates mixed read/write workloads. |
| Load (k6) | `k6 run tests/performance/k6-smoke.js --env GATEWAY_HOST=<url>` | Validates cache-heavy traffic patterns. |

The GitHub Actions workflow (`.github/workflows/ci.yml`) installs dependencies
and runs `pytest` on every push and pull request. Add optional linters or type
checkers by extending the workflow matrix.

Install additional developer tooling (Locust, Bandit, pip-audit) with
`pip install -r requirements-dev.txt`.

## Documentation map

- [`docs/performance/benchmarks.md`](docs/performance/benchmarks.md) – Latest
  Locust/k6 benchmark results and SLA targets.
- [`docs/security_audit.md`](docs/security_audit.md) – Release audit checklist
  for static analysis, dependencies and incident response.
- [`docs/operations`](docs/operations) – Deployment, performance tuning and
  service discovery runbooks.
- [`deploy/monitoring`](deploy/monitoring) – Prometheus/Alertmanager
  configuration validated in staging (alerts routed to Slack).

## Observability & monitoring

- Exposes `/metrics` for Prometheus scraping (see `deploy/monitoring`).
- Structured request logs (JSON) include request IDs, JWT subject and trace IDs
  when OpenTelemetry is enabled.
- Alerting rules detect error-rate spikes and latency SLO violations and trigger
  Slack notifications via Alertmanager.

## Contributing

1. Create a feature branch.
2. Run `pytest` locally and ensure load test scripts still execute.
3. Update documentation/CHANGELOG entries for user-facing changes.
4. Open a pull request; CI must pass before merging.

See [`docs/developer`](docs/developer) for module-specific guidelines and
transformation examples.
