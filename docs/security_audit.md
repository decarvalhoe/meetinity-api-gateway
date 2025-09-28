# Security Audit Checklist

This checklist is used during the security review of the Meetinity API Gateway
before every release. Each item should be verified and recorded in the audit
tracker.

## Static analysis

- [ ] Run `pip install -r requirements-dev.txt` (if available) and execute
      `bandit -r src` to analyse Python code for common vulnerabilities.
- [ ] Ensure `mypy` or `pyright` passes with no high-severity findings.
- [ ] Review custom Flask middleware for request validation and output encoding.
- [ ] Confirm JWT handling enforces issuer/audience/expiry checks and that
      secrets are rotated according to policy.

## Dependency review

- [ ] Execute `pip list --outdated --format=json` and document any critical
      upgrades.
- [ ] Run `pip-audit` (or `safety check`) and triage CVEs; ensure justifications
      exist for ignored advisories.
- [ ] Verify Docker base images are patched and built within the last 30 days.
- [ ] Check OS-level packages used in production images for high/critical CVEs
      via `grype` or similar.

## Configuration and secrets

- [ ] Validate `.env` files and Kubernetes secrets do not contain placeholder
      values in production.
- [ ] Ensure TLS certificates (ingress/load balancer) are valid for at least
      30 days.
- [ ] Confirm rate limiting, circuit breaking, and authentication middleware are
      enabled in production configuration.

## Observability and logging

- [ ] Confirm Prometheus alerting rules cover error rate and latency SLOs.
- [ ] Verify structured logs redact PII and secrets; test redaction filters.
- [ ] Ensure log retention policies meet compliance requirements (minimum 90
      days for staging, 180 days for production).

## Incident response

- [ ] Confirm on-call rotation and Slack/Email notification channels are current.
- [ ] Review the latest penetration test findings and confirm remediation status.
- [ ] Ensure runbooks in `docs/operations/` are up to date and linked from the
      on-call handbook.
