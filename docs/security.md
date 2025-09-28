# Sécurité du portail Meetinity

Ce document décrit les mécanismes de sécurité exposés par la passerelle :

- gestion des clés API et du middleware associé ;
- intégration OAuth 2.0 / OpenID Connect ;
- signature HMAC des requêtes et vérification côté passerelle ;
- filtrage IP (listes blanches/noires) et limitation par client.

## Clés API

Les clés sont définies via la variable d'environnement `API_KEYS` au format
`<identifiant>:<secret>` séparés par des virgules. Les secrets sont salés et
hachés (`API_KEY_SALT`, `API_KEY_HASH_ALGORITHM`) avant d'être stockés en
mémoire. Le middleware `APIKeyMiddleware` impose la présence de l'en-tête
`API_KEY_HEADER` (par défaut `X-API-Key`) sur toutes les routes non listées dans
`API_KEY_EXEMPT_PATHS`.

- Activer/désactiver : `API_KEY_REQUIRED` (`true` par défaut si des clés sont
  configurées).
- Exemptions : valeur séparée par des virgules, `/health` est appliqué par
  défaut.

## OAuth 2.0 / OpenID Connect

Lorsqu'`OAUTH_PROVIDER_URL` est défini, la passerelle instancie un
`OIDCProvider` qui réalise la découverte de métadonnées (`/.well-known/openid-configuration`)
avec un cache configurable (`OAUTH_CACHE_TTL`). Le validateur supporte les
jetons HMAC (`client_secret`) et RSA (JWKS), vérifie l'issuer, l'audience et les
claims obligatoires (`exp`, `iat`). Les paramètres optionnels :

- `OAUTH_AUDIENCE` pour l'audience attendue côté passerelle ;
- `OAUTH_CLIENT_SECRET` pour les signatures HMAC.

Les erreurs de validation retournent des exceptions `TokenValidationError` et la
métadonnée est exposée via `app.extensions['oidc_provider']`.

## Signatures HMAC des requêtes

Le middleware `RequestSignatureMiddleware` valide les requêtes entrantes à l'aide
d'une signature HMAC SHA-256 sur une représentation canonique : méthode,
chemin, corps haché et en-têtes optionnels (`SIGNATURE_HEADERS`). Les secrets
sont fournis via `SIGNING_SECRETS` (`<client>:<secret>`). Les options :

- `SIGNATURE_HEADER`, `SIGNATURE_TIMESTAMP_HEADER`, `SIGNATURE_KEY_ID_HEADER` ;
- `SIGNATURE_ALGORITHM` (algo HMAC, défaut `sha256`) ;
- `SIGNATURE_CLOCK_TOLERANCE` (en secondes, défaut 300) ;
- `SIGNATURE_EXEMPT_PATHS` (par défaut `/health`) ;
- `REQUEST_SIGNATURES_ENABLED` pour activer/désactiver (activé automatiquement
  si des secrets sont fournis).

L'outil `RequestSigner` facilite la génération de signatures côté client.

## Filtrage IP et limitation

Les variables `IP_WHITELIST` et `IP_BLACKLIST` permettent de restreindre l'accès
par adresse IP (valeurs séparées par des virgules). Les accès refusés renvoient
un statut HTTP 403 et sont journalisés.

Le `Limiter` utilise désormais l'en-tête `API_KEY_HEADER` pour dériver la clé de
limitation : lorsqu'une clé API est fournie, la limite s'applique par client,
sinon l'adresse IP (`get_remote_address`) est utilisée. Les limites existantes
(`RATE_LIMIT_AUTH`, etc.) continuent de fonctionner.
