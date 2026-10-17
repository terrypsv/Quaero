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
- [x] Pied de page pleine largeur, en bas de la fenêtre sur l'accueil, à la
      suite de la liste quand elle est plus longue
- [x] Cent dépôts par formulation, affichage par 5, 20, 50, 100 ou tous,
      "charger la suite" avec son coût en requêtes
- [ ] Validation d'usage réel sur des recherches quotidiennes
- [x] Release multi-plateforme

## v0.2.0 - recherche sémantique

- [ ] Réordonnancement par embeddings, derrière une interface enfichable
- [ ] Indexation locale des README des résultats, pour comparer le fond
- [ ] Recherche par similarité: "comme tel dépôt, mais en rust"
- [ ] Historique local des recherches, sans télémétrie

## v0.3.0 - décision

- [ ] Comparaison côte à côte de plusieurs candidats
- [ ] Signaux de gouvernance: nombre de mainteneurs actifs, cadence des versions
- [ ] Export du verdict de santé, réutilisable par un outil d'analyse de dépendances

## v0.4.0 - audit de code

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
- [x] `-scan owner/repo`: clone superficiel d'un dépôt public GitHub, scan,
      puis effacement du clone. Cible nommée à la main, jamais cherchée.
      Environnement des moteurs durci pour du code tiers (GOTOOLCHAIN=local,
      CGO_ENABLED=0, pas de hooks ni de sous-modules)
- [x] Chemins des constats relatifs au dépôt: un même constat garde le même
      identifiant d'un scan à l'autre, même sur deux clones
- [x] Premier audit de Quaero par lui-même: trois candidats triés (G101 sur
      des noms de variables, urllib limité à https, SRI sur une icône en
      data: URI), corrigés ou justifiés dans le code
- [x] `-advisory`: brouillon de signalement privé (forme GitHub Security
      Advisory) à partir d'un constat, commit analysé noté dans le rapport,
      liste de contrôle avant envoi, rien n'est envoyé par l'outil
- [x] Session locale par jeton remise (cookie `HttpOnly` `SameSite=Strict`,
      jeton tiré à chaque lancement), ouverte par le navigateur que Quaero
      lance lui-même: plus aucun lien à copier
- [x] Identifiant complet des règles semgrep conservé dans les preuves, pour
      des annotations `nosemgrep` précises
- [x] Onglet « auditer » dans l'interface, un dépôt public nommé à la main,
      une analyse à la fois, annulable, moteurs et constats affichés,
      brouillon de signalement à copier ou enregistrer, rien n'est envoyé.
      Lien « auditer » sur chaque résultat de recherche, sans lancement
- [x] Lancer et annuler en `POST` seulement, refusés depuis une autre origine
      (une page servie sur un autre port de la machine est du même site)
- [x] Ctrl+C arrête l'analyse en cours et efface son clone, en ligne de
      commande comme depuis l'interface. Aucun rapport n'est écrit pour un
      scan interrompu
- [x] Page de session réduite à une ligne
- [x] Arrêt de tout l'arbre de processus d'un moteur ou d'un clone
      interrompu (groupe de processus, `taskkill /T` sous Windows), effacement
      du clone réessayé, clones oubliés signalés au démarrage
- [x] Démarrage sans jeton, recherche limitée par GitHub et signalée dans
      l'interface, audit inchangé
- [x] Dépôts privés, par leur dossier ou par leur nom avec un jeton qui peut
      les lire, tenté seulement après un refus anonyme. Aucun gestionnaire
      d'identifiants sollicité
- [x] Dossier local dans l'onglet « auditer », nommé par son chemin complet
- [x] Constats de deux moteurs sur la même ligne fusionnés, titres semgrep
      réduits à la première phrase
- [x] Vulnérabilités publiées regroupées par dépendance, filtres gravité et
      type
- [x] Jeton de session exigé en en-tête pour l'API, le cookie n'ouvrant plus
      que la page. Un autre serveur de 127.0.0.1 qui reçoit le cookie ne peut
      rien en faire
- [x] Limite d'analyse affichée dans l'onglet audit, à la place du quota
- [x] Échecs de clone dits en une ligne, un message par cas
- [x] Logo du README, Quaero avec un Q majuscule, sur fond sombre, et
      logotype « Quaero » dans l'interface

## v0.5.0 - du constat au signalement

Trier vite et bien ce que les moteurs relèvent, puis préparer le signalement
de ce qui tient.

- [x] Rapports enregistrés au choix sur la machine, rouverts sans réseau,
      importés depuis un fichier `-scan-json`. Le brouillon de signalement se
      prépare depuis n'importe quel rapport
- [x] Tri des constats sans modèle de langage, avec des états gardés d'une
      analyse à l'autre (à vérifier, faux positif, confirmé, signalé) et un
      pré-tri par règles (tests, exemples, code généré, CI, atteignabilité)
- [ ] Décisions de tri aussi sur les dépendances vulnérables
- [ ] Bac à sable d'exécution pour analyser un dépôt tiers non fiable
- [ ] En dernier recours seulement, tri assisté par un modèle de langage

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
