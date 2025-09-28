# Observabilité de l'API Gateway

Ce document décrit la configuration de la journalisation structurée, des métriques
Prometheus et de la traçabilité distribuée à l'aide d'OpenTelemetry.

## Journalisation structurée

Le module `src/observability/logging.py` configure un logger JSON commun à
l'ensemble de l'application. Les journaux sont émis sur `stdout` et peuvent être
redirigés vers plusieurs agrégateurs réseau grâce à la variable d'environnement
`LOG_AGGREGATORS` (valeurs séparées par des virgules, ex. `udp://logstash:5000`).

Chaque entrée de log inclut :

* les métadonnées HTTP (méthode, route, statut, durée, identifiant de requête),
* l'utilisateur authentifié (`user_id` lorsqu'il est disponible),
* les identifiants de traçage (`trace_id`, `span_id`) issus d'OpenTelemetry.

Le middleware `src/middleware/logging.py` enrichit les journaux et met à jour les
métriques pour chaque réponse sortante.

## Métriques Prometheus

Le module `src/observability/metrics.py` expose des compteurs et histogrammes sur
`/metrics` au format Prometheus :

* `api_gateway_http_requests_total` (par méthode, endpoint, statut),
* `api_gateway_http_request_duration_seconds` (latence des requêtes HTTP),
* `api_gateway_upstream_request_duration_seconds` (latence des appels
  upstream, par service et statut),
* `api_gateway_upstream_failures_total` (erreurs réseau ou applicatives).

## Traçabilité distribuée

`src/observability/tracing.py` configure OpenTelemetry avec une ressource
`service.name=api-gateway`. Les exporteurs suivants sont supportés via
`OTEL_EXPORTER` :

* `otlp` (par défaut, compatible Jaeger/Zipkin via OTLP),
* `console` pour un export local en développement.

Des variables optionnelles permettent d'ajuster l'export OTLP :

* `OTEL_EXPORTER_OTLP_ENDPOINT` ou `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`,
* `OTEL_EXPORTER_OTLP_HEADERS` (liste `clé=valeur`).

Le module instrumente Flask et la librairie `requests`. Le proxy (`src/routes/proxy.py`)
crée des spans `proxy.forward` et `proxy.upstream_request` enrichis avec les
attributs HTTP, l'identifiant de requête ainsi que le service cible.

## Endpoints de santé

Des checks détaillés sont disponibles :

* `GET /health` : synthèse globale (gateway, user-service, service-registry,
  observability, oidc),
* `GET /health/<service>` : détail par dépendance avec statut (`up`, `degraded`,
  `down`, `skipped`).

Les contrôles vérifient la connectivité vers le user-service, l'état du registre
de services, la présence de l'instrumentation observabilité et, si configuré, la
capacité du fournisseur OIDC à répondre.
