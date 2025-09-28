# Transformation Pipeline

Le pipeline de transformation permet d'appliquer des règles configurables aux
requêtes entrantes et aux réponses en sortie avant qu'elles ne soient transmises
au service amont. Les règles sont décrites en YAML ou JSON et chargées au démarrage
de l'application via la variable d'environnement `TRANSFORMATION_RULES_PATH` (chemin
vers un fichier) ou `TRANSFORMATION_RULES` (contenu brut YAML/JSON).

## Structure générale

```yaml
request:
  headers:
    set:
      X-Injected: valeur
    remove:
      - X-Deprecate
  body:
    conversions:
      - type: format        # format | style
        from: json          # json | xml | csv (optionnel si dérivable du Content-Type)
        to: xml
      - type: style
        name: rest_to_graphql  # rest_to_graphql | graphql_to_rest
  validation:
    openapi:
      spec: ./openapi.yaml   # chemin absolu ou relatif au répertoire racine
      version: "3.0"         # optionnel, 3.0 par défaut

response:
  headers:
    remove: [X-Internal]
  body:
    conversions:
      - type: style
        name: graphql_to_rest
routes:
  - match:
      path_prefix: /api/users
      methods: [POST]
    request:
      headers:
        set:
          X-Users-Rule: active
```

- La section `request` s'applique aux requêtes envoyées vers l'amont.
- La section `response` s'applique aux réponses reçues de l'amont.
- La clé `routes` permet de définir des règles supplémentaires conditionnées sur
  un préfixe d'URL (`path_prefix`) et/ou une liste de méthodes HTTP.

## Types de conversions

### Conversion de formats

Le type `format` convertit le corps entre JSON, XML et CSV. Le `Content-Type`
est mis à jour automatiquement.

### Conversion de styles REST/GraphQL

- `rest_to_graphql` enveloppe une requête REST dans un document GraphQL contenant
  les informations de méthode, de chemin, de paramètres de requête et de corps.
- `graphql_to_rest` effectue l'opération inverse en reconstituant une description
  REST (méthode, chemin, paramètres, corps).

Ces conversions sont disponibles pour les requêtes et les réponses.

## Validation OpenAPI

La validation OpenAPI est effectuée avant l'envoi de la requête à l'amont et
après réception de la réponse. Fournissez un chemin vers un fichier OpenAPI 3.x.
En cas d'erreur de validation, la requête est rejetée (HTTP 400) ou la réponse
est transformée en erreur 502.

## Chargement des règles

Dans `create_app`, les règles sont chargées et le pipeline est enregistré sous
`app.extensions["transformation_pipeline"]`. L'absence de règles n'active aucun
traitement supplémentaire.

## Tests

Le fichier `tests/test_transformations.py` contient des exemples couvrant
l'injection d'en-têtes, la conversion de formats, la traduction REST⇔GraphQL et
les erreurs de validation OpenAPI.
