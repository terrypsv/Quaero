# Feuille de route

## v0.1.0 - recherche par intention

- [x] Lecture d'une phrase vers des facettes GitHub, avec restitution
- [x] Lecture mot à mot, chaque mot rendu tel que tapé avec ce qu'il a donné
      (terme, langage, étoiles, récence, mot générique ou vide)
- [x] Formes fléchies sans reste ("maintenues" ne laisse plus "es") et mots
      reconnus depuis leur début ("inactif" n'est plus lu comme "actif")
- [x] Client de l'API de recherche, quota exposé
- [x] Classement par pertinence, nom prioritaire sur popularité
- [x] Verdict de santé par dépôt, expliqué
- [x] Interface web embarquée, filtres par niveau de santé
- [x] Interface Index, phrase relue et surlignée mot à mot, santé en carrés,
      polices embarquées sous licence OFL
- [x] Interface allégée, une chose à la fois, options et raisons du rang
      repliées
- [x] Phrase d'accueil, critères compris affichés un par un avec le mot
      d'origine, mots laissés de côté expliqués, exemples tirés de la sécurité
- [x] Langue des dépôts au choix (anglais, français, toutes langues), le
      français cherche les mots tels que tapés
- [x] Vocabulaire de la sécurité étendu, expressions connues lues avant les
      mots de fraîcheur ("active directory")
- [x] Ouverture automatique dans le navigateur, `-no-browser` pour s'en passer
- [x] Geist pour lire, sans étirement, JetBrains Mono pour recopier
- [x] Quota de recherche visible en permanence, jauge et compte à rebours,
      lu sur `/rate_limit` sans être dépensé
- [x] Pages gardées dix minutes, un changement de tri ne repaie pas la
      recherche
- [x] Bloc pour resserrer une liste trop longue (langage, sujet, mise à jour,
      popularité), critères appliqués chez GitHub et retirables
- [x] Une cinquantaine d'exemples de sécurité, huit à la fois, phrase en
      français ou en anglais
- [x] Mots écartés dans la phrase ("pas de", "sauf", "hors", "-mot"), licence
      lue dans la phrase, "sans agent" lu comme une caractéristique
- [x] Critères licence, auteur et listes awesome pour resserrer la liste
- [x] Langue réelle de la description (anglais, français, chinois, russe...)
      au lieu de l'écriture
- [x] Lecture de la phrase pendant la frappe, sans dépenser le quota
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
- [x] Moteurs retrouvés hors du `PATH` (GOBIN, GOPATH/bin, ~/go/bin,
      ~/.local/bin), le message d'absence dit où ils ont été cherchés
- [x] Fusion des doublons entre moteurs, reconnus à un identifiant public
      partagé (OSV, CVE, GHSA). Le constat le plus informatif reste, la
      provenance garde tous les moteurs d'accord
- [x] Tout constat en `review`, `declared=false`: l'outil trie des candidats,
      il ne confirme ni ne déclare rien
- [x] Moteurs en parallèle, délai par moteur (`-scan-timeout`), durées au
      rapport
- [x] Code de sortie lu moteur par moteur: une panne ou un dépôt sans
      manifeste ne passe plus pour un dépôt sain
- [x] semgrep sans télémétrie (`--metrics=off`, `p/default`), utilisable sous
      Windows via pipx ou uv
- [x] Contrôle de `Host` contre le DNS rebinding, politique de contenu stricte
- [ ] Session locale par jeton (lien du terminal, cookie `HttpOnly`
      `SameSite=Strict`), retirée pendant le développement de l'interface. À
      remettre avant la première version publiée et avant toute route qui
      lance un moteur d'analyse (voir PR #29 pour l'implémentation)
- [x] Identifiant complet des règles semgrep conservé dans les preuves, pour
      des annotations `nosemgrep` précises
- [ ] Arrêt de tout l'arbre de processus d'un moteur interrompu, avec gestion
      de Ctrl+C. Aujourd'hui seul le moteur est arrêté, ses éventuels
      sous-processus peuvent finir seuls après la fin du scan
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
