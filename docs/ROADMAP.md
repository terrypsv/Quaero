# Feuille de route

## v0.1.0 - recherche par intention

- [x] Lecture d'une phrase vers des facettes GitHub, avec restitution
- [x] Client de l'API de recherche, quota expose
- [x] Classement par pertinence, nom prioritaire sur popularite
- [x] Verdict de sante par depot, explique
- [x] Interface web embarquee, filtres par niveau de sante
- [ ] Validation d'usage reel sur des recherches quotidiennes
- [ ] Release multi-plateforme

## v0.2.0 - recherche semantique

- [ ] Reordonnancement par embeddings, derriere une interface enfichable
- [ ] Indexation locale des README des resultats, pour comparer le fond
- [ ] Recherche par similarite: "comme <depot>, mais en rust"
- [ ] Historique local des recherches, sans telemetrie

## v0.3.0 - decision

- [ ] Comparaison cote a cote de plusieurs candidats
- [ ] Signaux de gouvernance: nombre de mainteneurs actifs, cadence des versions
- [ ] Export du verdict de sante, reutilisable par un outil d'analyse de dependances

## Hors perimetre

- Substitut a l'interface GitHub: Quaero repond a une question de recherche,
  il ne gere ni issues, ni pull requests, ni code.
- Recherche dans les depots prives: le perimetre est public, deliberement.
- Telemetrie: aucune recherche n'est envoyee ailleurs qu'a l'API GitHub.
