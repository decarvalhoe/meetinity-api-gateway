# Passerelle API Meetinity

La passerelle API Meetinity constitue le point d'entrée unique de la plate-forme.
Elle termine les connexions clientes, authentifie les requêtes, applique les
politiques transverses (limitation de débit, cache, observabilité) et relaie les
appels vers les microservices adaptés.

## Points forts

- **Routage flexible** – Découverte de service dynamique, répartition pondérée
  et circuits coupe-feu maintiennent un trafic résilient vers l'amont.
- **Sécurité native** – Middleware JWT, politiques CORS configurables et logs
  structurés protègent les interfaces publiques.
- **Observabilité intégrée** – Exposition Prometheus, traces distribuées et
  journaux JSON facilitent l'investigation.
- **Performance garantie** – Cache de réponses, déduplication "single-flight"
  et tests de charge automatisés (Locust/k6) couvrent les objectifs de latence.

## Démarrage rapide

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app src.app run --debug
```

Les variables d'environnement clés sont décrites dans
[`docs/operations/deployment.md`](docs/operations/deployment.md) (timeouts,
limites de débit, secrets JWT, exporteurs OpenTelemetry, etc.).

## Tests et qualité

| Type | Commande | Notes |
| --- | --- | --- |
| Unitaires / intégration | `pytest` | Couvre middleware, analytique, cache et découverte de service. |
| Charge (Locust) | `locust -f tests/performance/locustfile.py --host=<passerelle>` | Simule un mix lecture/écriture réaliste. |
| Charge (k6) | `k6 run tests/performance/k6-smoke.js --env GATEWAY_HOST=<url>` | Valide les scénarios orientés cache. |

Le workflow GitHub Actions (`.github/workflows/ci.yml`) installe les dépendances
et exécute `pytest` sur chaque push ou pull request.

Installez les outils développeur additionnels (Locust, Bandit, pip-audit) avec
`pip install -r requirements-dev.txt`.

## Carte documentaire

- [`docs/performance/benchmarks.md`](docs/performance/benchmarks.md) – Résultats
  Locust/k6 et objectifs SLA.
- [`docs/security_audit.md`](docs/security_audit.md) – Checklist audit sécurité
  (analyse statique, dépendances, réponse incident).
- [`docs/operations`](docs/operations) – Guides déploiement, tuning performance
  et découverte de services.
- [`deploy/monitoring`](deploy/monitoring) – Configuration Prometheus/Alertmanager
  validée en staging (alertes Slack).

## Observabilité & monitoring

- Endpoint `/metrics` à scruter avec Prometheus (voir `deploy/monitoring`).
- Logs de requêtes JSON enrichis (ID de requête, sujet JWT, identifiants de
  trace).
- Règles d'alerte détectant taux d'erreurs anormal ou dépassement de latence,
  avec notifications Slack via Alertmanager.

## Contribuer

1. Créer une branche de fonctionnalité.
2. Exécuter `pytest` et vérifier les scripts de charge.
3. Mettre à jour la documentation et le CHANGELOG pour les changements visibles.
4. Ouvrir une pull request et attendre la validation CI.
