# Portail développeur – Intégration

Le portail développeur Meetinity fournit un espace unique pour l’onboarding des équipes produit et partenaires. Ce document décrit l’intégration du portail avec l’API Gateway, notamment l’authentification SSO et le provisioning automatisé des clés d’API.

## Authentification SSO

* **Fédération d’identité** : le portail s’appuie sur le fournisseur OIDC configuré via `OAUTH_PROVIDER_URL`. Lorsqu’un développeur se connecte, le portail récupère un jeton d’accès signé et inscrit l’identifiant (`sub`) dans le registre interne.
* **Flux d’approbation** : les administrateurs valident les demandes d’accès dans le portail. Une fois approuvée, l’application cliente est associée à un ou plusieurs environnements (sandbox, production) et les audiences correspondantes sont stockées côté portail.
* **Synchronisation gateway** : la gateway consomme les métadonnées d’issuer via l’`OIDCProvider` et valide les JWT émis par le portail. Les politiques d’accès (rôles, limites de trafic) sont ensuite appliquées au niveau des blueprints versionnés (`/v1`, `/v2`).

## Provisioning des clés d’API

* **Clés gérées** : le portail chiffre et stocke les clés dans HSM. Lorsqu’une clé est créée, un webhook appelle l’endpoint d’administration de l’API Gateway afin d’ajouter la clé hachée dans la variable d’environnement `API_KEYS`.
* **Rotation automatisée** : des tâches planifiées déclenchent la rotation. Le portail régénère les clés, notifie les équipes et invalide automatiquement les clés expirées dans le registre du gateway.
* **Traçabilité** : toutes les actions (création, rotation, révocation) sont publiées dans le topic `audit.api-gateway` et visibles dans les tableaux de bord analytics.

## Cycle de vie des versions d’API

* Les développeurs sélectionnent la version cible lors de la création d’une application. Les versions disponibles sont exposées par le portail à partir de l’extension `api_versions` du gateway.
* Le portail surface les en-têtes de dépréciation (`Deprecation`, `Sunset`, `Warning`) renvoyés par la gateway et prévient les équipes lorsque la date de fin approche.
* Les rapports générés via `AnalyticsCollector` sont importés dans le portail afin de suivre l’adoption par version, détecter les intégrations inactives et initier les migrations vers les nouvelles versions.

## Bonnes pratiques d’onboarding

1. Créer l’application dans le portail et associer un owner SSO.
2. Générer les clés d’API sandbox puis effectuer un appel de test sur `/v1/api/auth/ping`.
3. Configurer les limites de trafic et activer les alertes d’expiration de clés.
4. Planifier une revue trimestrielle des rapports analytics afin d’anticiper les dépréciations.
