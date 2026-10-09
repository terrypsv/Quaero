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

## v0.4.0 - audit de code (en cours)

De la santé du dépôt vers la sécurité de son code. Le périmètre reste la
lecture: Quaero analyse, il n'exploite rien.

- [x] `-scan <chemin>`: audit statique d'un dépôt **local** (déjà cloné),
      projeté dans le schéma de constat partagé
- [x] Moteurs multi-langages, choisis selon le dépôt: semgrep (SAST) et
      osv-scanner (dépendances, tous écosystèmes) partout, govulncheck et gosec
      quand un `go.mod` est présent
- [x] Tout constat en `review`, `declared=false`: l'outil trie des candidats,
      il ne confirme ni ne déclare rien
- [ ] Vue web des constats de code, à côté du verdict de santé
- [ ] Bac à sable d'exécution pour analyser un dépôt tiers non fiable

## Discipline (non négociable)

- Analyse statique de code **public ou local**, jamais de sondage ni
  d'exploitation d'un système en fonctionnement qu'on ne possède pas.
- Confirmation d'une faille: sur une instance locale montée soi-même.
- Divulgation **coordonnée** (GitHub Security Advisory) et ciblée. Pas de scan
  de masse: la valeur est dans un rapport vérifié, pas dans le volume.

## Hors périmètre

- Substitut à l'interface GitHub: Quaero répond à une question de recherche et
  lit du code pour l'auditer; il ne gère ni issues, ni pull requests, et
  n'écrit jamais dans un dépôt.
- Ciblage de masse ou énumération automatique de dépôts tiers: la sélection
  d'une cible reste un acte humain.
- Télémétrie: aucune recherche ni aucun chemin analysé n'est envoyé ailleurs
  qu'aux API et outils invoqués localement.
