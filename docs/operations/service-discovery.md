# Service discovery et résilience du proxy

Ce document décrit la configuration du registre de services et des mécanismes de
résilience intégrés à l'API Gateway.

## Variables d'environnement

La factory `create_app` lit les variables ci-dessous pour configurer le registre
et le middleware de résilience :

| Variable | Description | Valeur par défaut |
| --- | --- | --- |
| `USER_SERVICE_NAME` | Nom logique du service utilisateur. | `user-service` |
| `USER_SERVICE_URL` | URL utilisée comme repli si aucune instance n'est découverte. | *(vide)* |
| `USER_SERVICE_STATIC_INSTANCES` | Liste d'instances statiques séparées par des virgules. Chaque entrée peut contenir un poids sous la forme `https://exemple:8443|3`. | *(vide)* |
| `SERVICE_DISCOVERY_BACKEND` | Type de backend de découverte (`static` pour le moment). | `static` |
| `SERVICE_DISCOVERY_REFRESH_INTERVAL` | Durée (secondes) avant de rafraîchir le cache d'instances. | `30` |
| `LOAD_BALANCER_STRATEGY` | Stratégie de sélection (`round_robin`, `weighted`, `health`). | `round_robin` |
| `PROXY_TIMEOUT_CONNECT` | Timeout de connexion (secondes) côté proxy. | `2` |
| `PROXY_TIMEOUT_READ` | Timeout de lecture (secondes) côté proxy. | `10` |
| `RESILIENCE_MAX_RETRIES` | Nombre de nouvelles tentatives autorisées par requête. | `2` |
| `RESILIENCE_BACKOFF_FACTOR` | Facteur du backoff exponentiel (doublé à chaque tentative). | `0.5` |
| `RESILIENCE_MAX_BACKOFF` | Backoff maximum (secondes). | `5` |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | Nombre d'échecs successifs avant d'ouvrir le circuit. | `3` |
| `CIRCUIT_BREAKER_RESET_TIMEOUT` | Temps d'attente (secondes) avant de retenter un appel sur un circuit ouvert. | `30` |

## Stratégies de sélection d'instance

Le module `src/services/registry.py` expose plusieurs stratégies de
répartition. Elles peuvent être choisies via `LOAD_BALANCER_STRATEGY` et sont
écrites sous forme de plug-ins pouvant être étendus avec `register_strategy`.

- **round_robin** : alterne entre les instances disponibles en privilégiant les
  instances considérées comme saines.
- **weighted** : applique un round-robin déterministe où chaque instance est
  répliquée selon son poids (`weight`).
- **health** : privilégie les instances marquées saines et repasse en mode
  round-robin classique si toutes sont en échec.

Les instances statiques se déclarent via `USER_SERVICE_STATIC_INSTANCES` :

```text
https://svc-a.example|2,https://svc-b.example,https://svc-c.example|4
```

Ici `svc-c` recevra quatre fois plus de trafic que `svc-b` et deux fois plus que
`svc-a`.

## Middleware de résilience

`src/middleware/resilience.py` fournit :

- **Circuit breaker** : lorsqu'un nombre d'échecs consécutifs atteint
  `CIRCUIT_BREAKER_FAILURE_THRESHOLD`, l'instance est mise hors-circuit pendant
  `CIRCUIT_BREAKER_RESET_TIMEOUT` secondes.
- **Retry exponentiel** : les appels en échec sont retentés sur d'autres
  instances avec un délai initial `RESILIENCE_BACKOFF_FACTOR` et un maximum
  `RESILIENCE_MAX_BACKOFF`.
- **Bascule automatique** : en cas d'échec, le proxy sélectionne une autre
  instance disponible selon la stratégie configurée.

Quand toutes les instances échouent ou que les circuits sont ouverts, l'API
Gateway répond `503 Service Unavailable`. Les erreurs réseau ou les timeouts
épuisant toutes les tentatives déclenchent une réponse `502 Bad Gateway`.
