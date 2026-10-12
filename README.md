<img width="485" height="184" alt="ascii-art-text" src="https://github.com/user-attachments/assets/f68fb629-efe8-459d-889e-611113698594" />


# Quaero

Recherche de dépôts GitHub par intention, avec un verdict sur la santé de ce
qu'on trouve.

La recherche native de GitHub attend un langage de requête: qualificateurs,
deux-points, opérateurs de comparaison. Qui le connaît trouve tout, qui ne le
connaît pas obtient une correspondance de mots-clefs sur un README et un mur de
forks. Le manque n'est pas dans l'index, il est dans l'interface.

Quaero lit une phrase. `une bibliothèque go pour parser du yaml, encore
maintenue` devient des termes, un langage et une fenêtre de fraîcheur, et
l'outil affiche ce qu'il a compris pour qu'une phrase mal lue puisse être
corrigée plutôt que subie.

**Logiciel propriétaire.** Voir `LICENSE`.

## Ce qu'il ajoute vraiment

Chercher une bibliothèque pose deux questions, pas une. La première est
"est-ce que ça fait ce dont j'ai besoin". La seconde est "est-ce que je peux en
dépendre", et c'est celle que l'interface native n'aide pas à trancher.

Un compteur d'étoiles dit qu'un projet a été utile, pas qu'il l'est encore. Une
bibliothèque à quarante mille étoiles sans commit depuis trois ans est une plus
mauvaise dépendance qu'une obscure poussée la semaine dernière, et rien dans la
liste par défaut ne permet de les distinguer.

Chaque résultat porte donc un verdict de santé:

| Niveau | Signification |
|--------|---------------|
| sain | poussé dans les trois derniers mois |
| calme | moins d'un an, ce qui peut être normal pour une bibliothèque finie |
| dormant | entre un et deux ans sans envoi |
| abandonné | plus de deux ans, considérer le projet comme arrêté |
| archivé | archivé par son propriétaire, il ne recevra plus de correctif |

Un dépôt dont la date d'envoi est absente n'est jamais déclaré sain: affirmer
la santé à partir d'une donnée manquante serait pire que ne rien dire.

## La phrase est en français, la requête part en anglais

GitHub indexe des noms de dépôts, des descriptions et des README, et ils sont
massivement en anglais. Une phrase tapée en français doit donc franchir la
barrière de langue avant de devenir une requête, sinon elle ne correspond à
rien.

Deux mécanismes s'en chargent, et le premier compte plus que le second.

Les mots qui décrivent le *genre* de la chose cherchée sont écartés.
"bibliothèque", "outil", "module": personne n'écrit "library" dans la
description de sa bibliothèque. Comme GitHub combine les termes en ET, un seul
mot qui ne correspond à rien vide tout le résultat: garder "bibliothèque"
suffisait à ne rien trouver.

Le vocabulaire technique courant est traduit, y compris les expressions qui
n'ont de sens qu'en groupe. "ligne de commande" devient `cli`, "base de
données" devient `database` et non "database data", qui ramènerait la moitié
de GitHub.

Chaque mot revient avec ce qu'il a donné (terme cherché, langage, plancher
d'étoiles, fenêtre de fraîcheur, mot générique écarté ou mot vide), et
l'interface réaffiche la phrase telle qu'elle a été tapée, mots compris
surlignés. Un mot n'est reconnu qu'à partir de son début, "inactif" ne vaut
pas "actif". Une forme fléchie ne laisse pas de reste, "maintenues" ne fait
plus chercher "es".

## Quand rien ne correspond

Une page vide est la pire réponse possible: elle ne distingue pas "ça n'existe
pas" de "la requête était trop serrée". Quaero desserre alors les contraintes
une par une, de la moins signifiante à la plus signifiante, et dit ce qu'il a
lâché.

L'ordre est délibéré. La fraîcheur et la popularité cèdent en premier, parce
que la phrase les a rarement exigées. Les termes cèdent en dernier, parce
qu'ils sont la question elle-même.

Un résultat trouvé après desserrage reste un résultat. Un résultat trouvé en
silence après desserrage serait un mensonge.

## Installation

```bash
go build -o quaero ./cmd/quaero
```

Un jeton GitHub est obligatoire. Sans lui, l'API limite à 60 requêtes par
heure, ce qu'une seule session épuise. Le jeton n'a besoin d'aucune permission:
la recherche publique n'en demande pas.

Le plus simple est de l'enregistrer une fois:

```bash
./quaero -save-token <jeton>
./quaero
```

Il est écrit dans `~/.quaero/config.json`, en lecture réservée au propriétaire.
`./quaero -forget-token` l'efface.

Pour une session seulement, la variable d'environnement fonctionne toujours et
prime sur le fichier:

```bash
export GITHUB_TOKEN=...        # bash
$env:GITHUB_TOKEN="..."        # PowerShell
```

Le jeton est cherché dans cet ordre, `GITHUB_TOKEN`, `GH_TOKEN`, puis le
fichier. GitHub répond `Bad credentials` de la même façon pour un jeton expiré,
révoqué ou mal copié, alors un refus nomme l'endroit où le jeton a été lu et le
remède qui va avec (remplacer la variable, ou `-save-token` / `-forget-token`
pour le fichier).

Le quota restant est affiché à chaque recherche, pour qu'une coupure imminente
se voie venir plutôt que de surprendre.

L'interface est sur `http://127.0.0.1:7777`. L'écoute est sur la boucle locale
par défaut, parce que le processus porte un jeton: un outil exposé sur toutes
les interfaces par défaut est un outil qui laisse fuir ce jeton la première
fois qu'il tourne sur un réseau qui n'est pas le sien.

### L'interface

Papier, encre, et un vert acide qui surligne ce que Quaero a compris. L'écran
montre une chose à la fois, la question puis les dépôts. Après une recherche,
la phrase revient telle qu'elle a été tapée, mots compris surlignés, mots
écartés barrés. Survoler un mot surligné montre ce qu'il est devenu dans la
requête, et la requête envoyée reste visible en dessous.

Chaque dépôt tient en trois lignes, nom et santé, description, puis étoiles,
langage, licence et date du dernier envoi. La santé se lit en quatre carrés,
pleins pour un projet actif, vides pour un projet archivé, sans avoir besoin
de la couleur. Les raisons du rang et du verdict se déplient sous chaque
dépôt, avec de quoi affiner la phrase. Les options de recherche (langues,
précision) restent repliées sous la barre.

Les polices (JetBrains Mono, Syne, et Archivo pour le logotype) sont embarquées
dans le binaire, puisque la politique de contenu n'autorise aucune ressource
extérieure. Elles sont sous licence SIL OFL 1.1, livrées avec leur licence dans
`internal/webui/fonts/`. `python scripts/polices.py` les récupère, à relancer
seulement pour en changer.

### Contrôle de l'hôte

Écouter sur 127.0.0.1 ne suffit pas. Une page web malveillante ouverte dans le
navigateur peut atteindre ce port par DNS rebinding, en faisant pointer un
domaine qu'elle contrôle vers 127.0.0.1. L'en-tête `Host` doit donc désigner
cette machine (`127.0.0.1`, `localhost`, `[::1]`, au bon port), sinon la
requête est refusée avant tout traitement. Ce contrôle ne demande rien à
l'utilisateur.

Les réponses portent une politique de contenu stricte (aucune ressource
extérieure, pas d'intégration dans un cadre) et `Referrer-Policy: no-referrer`.

La session par jeton (lien d'ouverture affiché dans le terminal, cookie
`HttpOnly` `SameSite=Strict`) est retirée le temps du développement de
l'interface. Elle reviendra avant la première version publiée, et avant
toute route qui lance un moteur d'analyse.

Écouter sur toutes les interfaces (`-addr 0.0.0.0:7777`) désactive le contrôle
de `Host`. Plus rien ne protège alors l'interface, et le terminal le signale.

## Ce que la phrase peut exprimer

| Ce qu'on écrit | Ce qui est compris |
|----------------|--------------------|
| `en go`, `du rust`, `python` | facette de langage |
| `maintenu`, `encore actif`, `recent` | fenêtre de fraîcheur |
| `populaire`, `tres utilise` | plancher d'étoiles |
| `au moins 2000 etoiles` | plancher explicite, prioritaire |
| `y compris les forks` | annule l'exclusion par défaut |
| `y compris archives` | annule l'exclusion par défaut |

Les forks et les dépôts archivés sont écartés par défaut: ils forment
l'essentiel du bruit dans les résultats natifs, et qui cherche une
bibliothèque à utiliser n'en veut presque jamais.

## Trier autrement

La bonne réponse n'est pas la même question pour tout le monde. Cinq
ordonnancements sont disponibles depuis l'interface:

| Mode | Ce qu'il remonte |
|------|------------------|
| pertinence | équilibre entre précision des termes, langage et santé |
| populaire | les projets largement adoptés d'abord |
| niche | les petits projets précis, entre 20 et 2000 étoiles, que la popularité enterre |
| récent | par date du dernier envoi |
| santé | les dépôts sur lesquels on peut le plus sûrement s'appuyer |

Le mode niche existe parce qu'un outil qui ne montre jamais que la réponse
célèbre est un outil incapable de trouver la réponse spécifique. Le plancher de
vingt étoiles est délibéré: en dessous, un projet n'est pas niche, il est
simplement non éprouvé.

## Pagination

GitHub ne restitue que mille résultats, quel que soit le nombre de
correspondances. Une recherche qui annonce onze mille dépôts n'en rend donc
accessibles que mille, et l'interface affiche les deux chiffres. Promettre des
pages qui reviendraient vides serait pire que d'annoncer la limite.

Cliquer un langage ou un sujet l'ajoute à la phrase et relance la recherche:
c'est le raffinement qu'on veut faire après avoir vu une première page.

## Le classement

La pertinence privilégie la précision sur la popularité. Un terme dans le nom
du dépôt vaut bien plus que le même terme noyé dans une description, parce que
nommer son projet d'après un concept signale généralement qu'on a construit ce
concept.

Les étoiles départagent, elles ne décident pas: leur contribution est
logarithmique, pour qu'un projet à cinquante mille étoiles n'efface pas le
champ.

Chaque résultat indique ce qui lui a valu sa place. Un classement que personne
ne peut interroger est un classement auquel personne ne devrait se fier.

## Audit de code

Au-delà de la santé d'un dépôt, Quaero audite la sécurité de son code. Le
périmètre reste la lecture: l'outil analyse un dépôt **déjà cloné sur le
disque**, il ne sonde ni n'exploite aucun système en fonctionnement.

```bash
quaero -scan /chemin/vers/un/depot
quaero -scan /chemin/vers/un/depot -scan-json rapport.json
quaero -scan /chemin/vers/un/depot -scan-timeout 30m
```

Quaero n'invente pas de moteur: il orchestre des analyseurs statiques établis,
**multi-langages**, et normalise leurs sorties dans le schéma de constat
partagé. Les moteurs sont choisis selon ce que contient le dépôt.

| Analyseur | Langages | Ce qu'il regarde |
|-----------|----------|------------------|
| semgrep | Go, Python, JS/TS, Java, PHP, Ruby, C... | motifs de code non sûrs |
| osv-scanner | tous écosystèmes (npm, PyPI, Go, Maven, crates...) | dépendances vulnérables connues (base OSV) |
| govulncheck | Go | dépendances vulnérables, et si le symbole fautif est *atteignable* |
| gosec | Go | motifs non sûrs propres à Go |

semgrep et osv-scanner se déclenchent partout; govulncheck et gosec ne
s'ajoutent que si un `go.mod` est présent. semgrep est le seul des quatre à
pouvoir relever une faille encore inconnue, les autres retrouvent des
vulnérabilités déjà publiées.

semgrep tourne avec le jeu de règles `p/default` et `--metrics=off`. Son mode
`auto` est évité: il repose sur l'envoi de métriques, dont une empreinte de
l'adresse du projet analysé, contraire au principe de Quaero de ne rien envoyer
sur ce qu'il analyse. Sous Windows, semgrep s'installe avec `pipx install
semgrep` ou `uv tool install semgrep`.

Un moteur est cherché dans le `PATH`, puis là où les installateurs le posent
sans toujours l'y ajouter, `GOBIN`, `GOPATH/bin`, `~/go/bin` pour `go install`
et `~/.local/bin` pour pipx et uv, Windows compris. Un moteur introuvable laisse un
constat d'information qui dit où il a été cherché, plutôt que de disparaître
du rapport.

Les moteurs tournent en parallèle, chacun sous un délai propre (15 minutes par
défaut, `-scan-timeout` pour le changer). Un moteur qui dépasse son délai est
interrompu et le rapport le dit. Le code de sortie de chaque moteur est lu
selon ses propres règles: un moteur en panne, ou osv-scanner qui ne trouve
aucun manifeste à vérifier, ne ressort jamais comme un dépôt sain. Le résumé
affiche la durée de chaque moteur.

Un faux positif se documente dans le code, à côté de la ligne concernée.
semgrep ignore les annotations `#nosec` de gosec: il attend
`// nosemgrep: <identifiant complet de la règle>` sur la ligne précédente.
L'identifiant complet figure dans chaque constat semgrep, en preuve de type
`rule`.

Deux moteurs qui signalent la même vulnérabilité connue, reconnue à un
identifiant partagé (OSV, CVE ou GHSA), ne font qu'un constat. Le plus
informatif est gardé, govulncheck en tête puisqu'il sait si le code fautif
est appelé, et chaque constat dit quels moteurs l'ont trouvé. Le rapport
indique combien de doublons ont été fusionnés.

Chaque constat sort en statut `review` et `declared=false`. L'analyse statique
produit des **candidats**, pas des verdicts: confirmer une faille se fait sur
une instance locale montée soi-même, et la déclarer passe par une divulgation
coordonnée (GitHub Security Advisory). L'outil trie, l'opérateur décide.

## Structure

```
internal/intent/    lecture de la phrase vers des facettes
internal/github/    appel de l'API de recherche, sans jugement
internal/rank/      pertinence et santé, deux jugements distincts
internal/audit/     santé des dépôts d'une requête, vers le schéma de constat
internal/codescan/  audit de code d'un dépôt local (govulncheck, gosec)
internal/finding/   schéma de constat partagé par la suite
internal/webui/     serveur HTTP, page et polices embarquées
scripts/polices.py  récupération des polices de l'interface
cmd/quaero/         point d'entrée
```

## Développement

```bash
go vet ./...
go test ./... -count=1
```
