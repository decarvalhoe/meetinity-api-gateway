# Passerelle API Meetinity

Ce repository contient la passerelle API de la plateforme Meetinity, servant de point d'entrée central pour toutes les requêtes clients et les routant vers les microservices appropriés.

## Vue d'ensemble

La passerelle API est développée avec **Python Flask** et fournit des fonctionnalités essentielles comme le routage des requêtes, l'authentification JWT, la limitation de débit et la gestion CORS. Elle agit comme un proxy inverse et une couche de sécurité pour l'architecture microservices de Meetinity.

## Fonctionnalités

- **Routage des requêtes** : Routage intelligent des requêtes vers les services backend appropriés
- **Authentification JWT** : Authentification sécurisée basée sur les tokens avec validation middleware
- **Limitation de débit** : Limitation de débit configurable pour prévenir les abus et assurer la stabilité du service
- **Support CORS** : Configuration Cross-Origin Resource Sharing pour les clients web
- **Surveillance de santé** : Points de contrôle de santé pour la surveillance des services et l'équilibrage de charge
- **Gestion d'erreurs** : Réponses d'erreur standardisées et gestion des exceptions

## Stack Technique

- **Flask** : Framework web Python léger
- **Flask-CORS** : Support Cross-Origin Resource Sharing
- **Flask-Limiter** : Fonctionnalité de limitation de débit
- **PyJWT** : Implémentation JSON Web Token
- **Requests** : Bibliothèque HTTP pour la communication avec les services en amont
- **Python-dotenv** : Gestion des variables d'environnement

## État du Projet

- **Avancement** : 40%
- **Fonctionnalités terminées** : Routage de base, middleware JWT, limitation de débit, configuration CORS, contrôles de santé
- **Fonctionnalités en attente** : Découverte de services, équilibrage de charge, transformation requête/réponse, journalisation complète

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env  # mettre à jour les valeurs si nécessaire
python src/app.py
```

## Tests

```bash
pytest
flake8
```

## Configuration

La passerelle utilise des variables d'environnement pour la configuration :

- `USER_SERVICE_URL` : URL du service utilisateur
- `JWT_SECRET` : Clé secrète pour la validation des tokens JWT
- `CORS_ORIGINS` : Liste séparée par des virgules des origines CORS autorisées
- `RATE_LIMIT_AUTH` : Limite de débit pour les points d'authentification (par défaut : "10/minute")

## Routes API

- `GET /health` - Point de contrôle de santé
- `POST /api/auth/*` - Routes d'authentification (limitation de débit)
- `GET|POST|PUT|DELETE /api/users/*` - Routes de gestion des utilisateurs (protégées JWT)
- `GET|POST|PUT|DELETE /api/profile/*` - Routes de gestion des profils (protégées JWT)
