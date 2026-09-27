# Feuille de route

## v0.1.0 - recherche par intention

- [x] Lecture d'une phrase vers des facettes GitHub, avec restitution
- [x] Client de l'API de recherche, quota exposé
- [x] Classement par pertinence, nom prioritaire sur popularité
- [x] Verdict de santé par dépôt, expliqué
- [x] Interface web embarquée, filtres par niveau de santé
- [ ] Validation d'usage réel sur des recherches quotidiennes
- [ ] Release multi-plateforme

## v0.2.0 - recherche sémantique

- [ ] Réordonnancement par embeddings, derrière une interface enfichable
- [ ] Indexation locale des README des résultats, pour comparer le fond
- [ ] Recherche par similarité: "comme tel dépôt, mais en rust"
- [ ] Historique local des recherches, sans télémétrie

## v0.3.0 - décision

- [ ] Comparaison côte à côte de plusieurs candidats
- [ ] Signaux de gouvernance: nombre de mainteneurs actifs, cadence des versions
- [ ] Export du verdict de santé, réutilisable par un outil d'analyse de dépendances

## Hors périmètre

- Substitut à l'interface GitHub: Quaero répond à une question de recherche,
  il ne gère ni issues, ni pull requests, ni code.
- Recherche dans les dépôts privés: le périmètre est public, délibérément.
- Télémétrie: aucune recherche n'est envoyée ailleurs qu'à l'API GitHub.
