# Guide de Quaero

Le fonctionnement de Quaero en détail. Pour l'installer et s'en servir, le
[README](../README.md) suffit.

## Pourquoi chercher autrement

La recherche native de GitHub attend un langage de requête: qualificateurs,
deux-points, opérateurs de comparaison. Qui le connaît trouve tout, qui ne le
connaît pas obtient une correspondance de mots-clefs sur un README et un mur de
forks. Le manque n'est pas dans l'index, il est dans l'interface.

Quaero lit une phrase. `une bibliothèque go pour parser du yaml, encore
maintenue` devient des termes, un langage et une fenêtre de fraîcheur, et
l'outil affiche ce qu'il a compris pour qu'une phrase mal lue puisse être
corrigée plutôt que subie.

## Ce qu'il ajoute vraiment

Chercher une bibliothèque pose deux questions, pas une. La première est
"est-ce que ça fait ce dont j'ai besoin". La seconde est "est-ce que je peux en
dépendre", et c'est celle que l'interface native n'aide pas à trancher.

Un compteur d'étoiles dit qu'un projet a été utile, pas qu'il l'est encore. Une
bibliothèque à quarante mille étoiles sans commit depuis trois ans est une plus
mauvaise dépendance qu'une obscure poussée la semaine dernière, et rien dans la
liste par défaut ne permet de les distinguer.

Chaque résultat porte donc un verdict de santé:

| Verdict | Signification |
|---------|---------------|
| actif | poussé dans les trois derniers mois |
| stable | moins d'un an, ce qui peut être normal pour une bibliothèque finie |
| ralenti | entre un et deux ans sans envoi |
| arrêté | plus de deux ans, considérer le projet comme arrêté |
| archivé | archivé par son propriétaire, il ne recevra plus de correctif |

Un dépôt dont la date d'envoi est absente n'est jamais déclaré sain: affirmer
la santé à partir d'une donnée manquante serait pire que ne rien dire.

## La phrase en français ou en anglais, la requête en anglais

GitHub indexe des noms de dépôts, des descriptions et des README, et ils sont
massivement en anglais. Une phrase tapée en français doit donc franchir la
barrière de langue avant de devenir une requête, sinon elle ne correspond à
rien. Une phrase tapée en anglais passe telle quelle, ses mots vides sont
écartés de la même façon.

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

Le vocabulaire de la sécurité est le mieux couvert, puisque c'est le domaine
de travail de Quaero. "scanner de ports" devient `port-scanner`, "détection
d'intrusion" devient `ids`, "pot de miel" devient `honeypot`, "rétro-ingénierie"
devient `reverse-engineering`, "commande et contrôle" devient `c2`. Une
expression connue passe avant les mots de fraîcheur qu'elle contient, "active
directory" est un produit et pas une demande de projets actifs, et "reverse
shell" n'est pas une demande de dépôts écrits en Shell. "analyse" se lit comme
un nom (analyse de binaires, de journaux), "analyser" reste le verbe qu'on
emploie pour un format.

Chaque mot revient avec ce qu'il a donné (mot-clé, langage, popularité,
fraîcheur, mot générique laissé de côté). L'interface affiche ce que Quaero a
compris, critère par critère, avec le mot d'origine quand il a été traduit, et
dit pourquoi un mot n'est pas cherché. Un mot n'est reconnu qu'à partir de son
début, "inactif" ne vaut pas "actif". Une forme fléchie ne laisse pas de reste,
"maintenues" ne fait plus chercher "es".

La langue des dépôts se choisit dans les options. **anglais** traduit la
phrase, c'est le réglage conseillé. **français** cherche les mots tels qu'ils
ont été tapés, pour trouver les projets décrits en français. **toutes langues**
ajoute des recherches avec le mot principal en français, chinois, japonais,
coréen, russe ou espagnol, selon le mot.

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

Quaero démarre sans jeton. Chacun utilise le sien, rien n'est lié au compte de
l'auteur. Sans jeton, GitHub limite la recherche à 10 requêtes par minute, soit
deux recherches approfondies, et l'interface le signale. L'audit d'un dépôt
public n'en a pas besoin. Un jeton sans aucune permission fait passer la
recherche à 30 requêtes par minute.

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

Le quota de recherche reste affiché en haut de la page, dès l'ouverture, pour
qu'une coupure se voie venir plutôt que de surprendre. GitHub autorise 30
requêtes de recherche par minute à tout compte authentifié, quel que soit
l'abonnement (GitHub Pro et le Student Developer Pack n'y changent rien), et le
compteur se remplit à la fin de chaque minute. Une recherche approfondie coûte
5 requêtes, une rapide 1, l'option toutes langues jusqu'à 6 de plus. La jauge
dit combien de recherches il reste et dans combien de secondes le quota sera
plein, et passe en négatif quand il ne suffit plus pour une recherche. Il est
lu sur `/rate_limit`, que GitHub ne décompte pas.

Les pages reçues de GitHub sont gardées dix minutes en mémoire. Changer de tri,
revenir à une page ou retirer un critère ne coûte donc aucune requête, le
classement se faisant dans Quaero et non chez GitHub.

L'interface s'ouvre seule dans le navigateur par défaut, sur
`http://127.0.0.1:7777`, session ouverte. `-no-browser` laisse le navigateur
fermé et affiche le lien de session dans le terminal. L'écoute est sur la boucle locale par défaut,
parce que le processus porte un jeton: un outil exposé sur toutes les
interfaces par défaut est un outil qui laisse fuir ce jeton la première fois
qu'il tourne sur un réseau qui n'est pas le sien.

### L'interface

Papier, encre, et un vert acide qui marque ce que Quaero a compris. Une phrase
en tête de page dit ce qu'est l'outil, le quota de recherche reste en vue à
côté du logotype. Huit exemples tirés de la sécurité sont proposés sous la
barre, pris dans une cinquantaine, et un test vérifie que chacun se lit sans
mot perdu. Après une recherche, chaque critère compris s'affiche avec sa
valeur (mot-clé, langage, popularité, fraîcheur), les mots laissés de côté
sont expliqués, et la requête envoyée reste visible.

Chaque dépôt tient en trois lignes, nom et santé, description, puis étoiles,
langage, licence et date du dernier envoi. La santé se lit en quatre carrés,
pleins pour un projet actif, vides pour un projet archivé, sans avoir besoin
de la couleur. Les raisons du rang et du verdict se déplient sous chaque
dépôt. Les options de recherche (langue des dépôts, précision) restent repliées
sous la barre, leur réglage affiché à côté.

Les polices (Geist pour le texte, les titres, le logotype et les exemples,
JetBrains Mono pour la requête à recopier) sont utilisées sans étirement et
embarquées dans le binaire, puisque la politique de contenu n'autorise aucune
ressource extérieure. Elles sont sous licence SIL OFL 1.1, livrées avec leur licence dans
`internal/webui/fonts/`. `python scripts/polices.py` les récupère, à relancer
seulement pour en changer.

### Session et contrôle de l'hôte

Écouter sur 127.0.0.1 ne suffit pas. Une page web malveillante ouverte dans le
navigateur peut atteindre ce port par DNS rebinding, en faisant pointer un
domaine qu'elle contrôle vers 127.0.0.1. L'en-tête `Host` doit donc désigner
cette machine (`127.0.0.1`, `localhost`, `[::1]`, au bon port), sinon la
requête est refusée avant tout traitement. Ce contrôle ne demande rien à
l'utilisateur.

Les réponses portent une politique de contenu stricte (aucune ressource
extérieure, pas d'intégration dans un cadre) et `Referrer-Policy: no-referrer`.

Chaque requête doit aussi porter le jeton de session, tiré au hasard au premier
lancement puis gardé dans `~/.quaero/session`, lisible par toi seul. Sous
Linux et macOS, un fichier lisible par d'autres n'est pas repris, un jeton neuf
le remplace. L'effacer en tire un neuf au lancement suivant. Quaero ouvre lui-même le navigateur
sur le lien qui le porte. Le jeton passe une fois dans l'adresse, disparaît de
la barre d'adresse, puis vit à deux endroits. Un cookie `HttpOnly`
`SameSite=Strict` ouvre la page et ses polices. L'API exige le jeton dans
l'en-tête `X-Quaero-Session`, que la page garde dans le stockage de son
origine. Un cookie ne distingue pas les ports, le navigateur l'envoie aussi à
tout autre serveur de 127.0.0.1, qui pourrait le rejouer. Le stockage de la
page, lui, est propre à son port, et une page d'un autre site ne peut pas
poser cet en-tête. Chercher, lire un rapport ou lancer une analyse demande
donc le jeton lui-même. Sans session, rien n'est servi, pas même les polices.
Avec `-no-browser`, le lien de session s'affiche dans le terminal.

Un onglet ouvert survit à une relance. La page tient une requête ouverte chez
Quaero. Quand il s'arrête, une ligne le dit en tête de page, et la page retente
chaque seconde. Relancé, Quaero attend deux secondes et demie. Si l'onglet se
manifeste, il reprend tout seul et aucun autre ne s'ouvre, sinon Quaero ouvre
le navigateur. Un onglet resté en arrière-plan longtemps peut être ralenti par
le navigateur, Quaero en ouvre alors un second. Si le jeton a changé, l'ancien
onglet affiche une seule ligne, « Session fermée ».

Ce qui change un état (lancer ou annuler une analyse) n'accepte que `POST`, et
seulement depuis la page elle-même. `SameSite` ne distingue pas les ports. Une
page servie sur un autre port de cette machine est du même site et le cookie
l'accompagne. Son en-tête `Origin`, lui, la trahit, et la requête est refusée.

Écouter sur toutes les interfaces (`-addr 0.0.0.0:7777`) désactive le contrôle
de `Host`. Seul le jeton protège alors l'interface, et le terminal le signale.
Les dossiers locaux et les rapports enregistrés sont alors fermés, et le jeton
est tiré à chaque lancement, jamais écrit.

## Ce que la phrase peut exprimer

| Ce qu'on écrit | Ce qui est compris |
|----------------|--------------------|
| `en go`, `du rust`, `python` | facette de langage |
| `maintenu`, `encore actif`, `recent` | fenêtre de fraîcheur |
| `populaire`, `tres utilise` | plancher d'étoiles |
| `au moins 2000 etoiles` | plancher explicite, prioritaire |
| `pas de nmap`, `sauf cowrie`, `hors windows`, `-nmap` | mot écarté (`NOT`) |
| `licence mit`, `sous licence apache` | licence (`license:`) |
| `y compris les forks` | annule l'exclusion par défaut |
| `y compris archives` | annule l'exclusion par défaut |

Les forks et les dépôts archivés sont écartés par défaut: ils forment
l'essentiel du bruit dans les résultats natifs, et qui cherche une
bibliothèque à utiliser n'en veut presque jamais.

Un mot écarté l'est en entier ("pas de go" n'écarte pas "google"), quatre au
plus, parce que GitHub refuse une requête de plus de cinq `NOT`. Il est aussi
retiré des résultats par Quaero, pour que l'exclusion tienne quelle que soit
la formulation qui a trouvé le dépôt. "sans" n'écarte rien: "sans agent",
"sans fichier" ou "sans dépendance" décrivent une caractéristique, et
deviennent `agentless`, `fileless` ou `zero-dependency`.

Pendant la frappe, une ligne sous la barre montre ce que Quaero cherchera,
écartera ou ignorera. Cette lecture ne demande rien à GitHub et ne coûte
aucune requête du quota.

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

Chaque formulation de la question demande cent dépôts à GitHub, le maximum
d'une page, pour le prix d'une seule requête. Une recherche approfondie en
charge donc jusqu'à cinq cents, souvent moins puisque les formulations se
recoupent. L'interface les affiche par 5, 20, 50 ou 100, ou tous à la fois,
et passe d'une page à l'autre sans rien redemander. Le choix est gardé dans le
navigateur.

Au bout de la liste chargée, "charger la suite" demande une page GitHub de
plus par formulation, et dit combien de requêtes du quota cela coûte. Les
pages déjà reçues reviennent du cache, le serveur classe le tout, et
l'interface garde à leur place les dépôts déjà affichés pour ajouter les
nouveaux à la suite. Une page incomplète est la dernière, Quaero n'en demande
pas d'autre, et dix pages de cent au plus, la limite de GitHub.

## Resserrer une liste trop longue

Tant que tout n'est pas chargé, un bloc propose de resserrer la liste avec ce
que contiennent les dépôts chargés eux-mêmes, chacun avec le nombre de dépôts
qui le portent.

| Critère | Ce qu'il ajoute à la requête |
|---------|------------------------------|
| langage | `language:` |
| sujet, trois au plus | `topic:` |
| listes, écarter les listes awesome | `NOT awesome -topic:awesome-list -topic:awesome` |
| mis à jour, moins de 3 mois ou d'un an | `pushed:>=` |
| popularité, 100, 1 000 ou 10 000 étoiles | `stars:>=` |
| licence | `license:` |
| auteur, quand il revient plusieurs fois | `user:` |

Quand la recherche dépasse les mille résultats que GitHub rend, le bloc le
dit. Un choix devient un qualificatif GitHub appliqué à toutes les
formulations de la question et aux autres langues. Il réduit donc le total, pas seulement la page affichée. Le langage
choisi remplace celui de la phrase, et pour les étoiles ou la fraîcheur le plus
exigeant des deux l'emporte. Les critères ajoutés s'affichent avec ce que
Quaero a compris et se retirent d'un clic. Le desserrage ne les retire jamais,
ce sont des exigences et non des suppositions. Une nouvelle question repart
sans eux.

La langue de la description, que GitHub ne connaît pas, est détectée par
Quaero, par l'écriture pour le chinois, le japonais, le coréen, le russe ou
l'arabe, et par les petits mots de chaque langue ("the", "pour", "und") pour
distinguer l'anglais du français, de l'espagnol, du portugais, de l'allemand
ou de l'italien. Un filtre l'utilise sur la page affichée, sans nouvelle
recherche, et le choix reste d'une page à l'autre tant que la question ne
change pas. Une description sans aucun petit mot ("SSH honeypot") compte comme
anglaise, ce qu'elle est presque toujours.

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
périmètre reste la lecture: l'outil analyse du code source, il ne sonde ni
n'exploite aucun système en fonctionnement.

`-scan` prend un chemin local, ou une référence de dépôt GitHub à cloner. Un
dépôt se nomme par `owner/repo` ou par son URL github.com. Quaero le clone en
superficiel dans un dossier temporaire, l'analyse, puis efface le clone.
Nommer la cible reste un acte humain, Quaero ne cherche pas de cible. Un
dossier local déjà présent l'emporte sur une référence de même forme.

### Dépôts privés

Un dépôt privé s'analyse de deux façons.

- Par son dossier, s'il est déjà cloné: `-scan <chemin>`, ou le chemin complet
  dans l'onglet « auditer ». Rien n'est cloné ni effacé, le code reste où il
  est.
- Par son nom, avec un jeton qui peut le lire. Quaero tente toujours le clone
  sans identifiant. Si GitHub le refuse, et seulement dans ce cas, il réessaie
  avec le jeton de l'utilisateur. Un dépôt public ne voit donc jamais passer le
  jeton. Un jeton à grain fin limité aux dépôts voulus, avec le seul droit
  « Contents » en lecture, suffit. Le jeton passe à git par l'environnement,
  jamais par la ligne de commande, et uniquement vers github.com.

Aucun gestionnaire d'identifiants n'est sollicité pendant le clone. Il n'y a
ni fenêtre de connexion ni identifiant enregistré utilisé à l'insu de
l'utilisateur.

Le code analysé ne quitte pas la machine. Les moteurs, eux, consultent des
bases publiques. osv-scanner envoie le nom et la version des dépendances à
OSV, govulncheck télécharge la base de vulnérabilités Go, semgrep télécharge
ses règles. Pour un dépôt dont même la liste des dépendances est
confidentielle, analyser sur une machine sans réseau reste la seule garantie.

```bash
quaero -scan /chemin/vers/un/depot
quaero -scan mushorg/cowrie
quaero -scan https://github.com/mushorg/cowrie
quaero -scan mushorg/cowrie -scan-json rapport.json
quaero -scan /chemin/vers/un/depot -scan-timeout 30m
```

Analyser du code tiers n'est pas sans risque: govulncheck charge le graphe des
paquets, ce qui compile le code analysé. Pour un dépôt cloné, Quaero durcit
donc l'environnement des moteurs, une chaîne d'outils Go qui ne peut pas être
remplacée par le `go.mod` de la cible (`GOTOOLCHAIN=local`), pas de cgo
(`CGO_ENABLED=0`, aucun compilateur C lancé sur la cible), pas d'invite
d'authentification. Le clone est superficiel, sans étiquettes, sans
sous-modules et sans hooks. Ce n'est pas une isolation complète, le bac à sable
d'exécution reste à faire: pour du code vraiment douteux, cloner et scanner
dans une machine jetable. Un scan local, lui, tourne sans ce durcissement.

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

Les chemins des constats sont ramenés au dépôt (`internal/github/github.go:83`),
quel que soit l'endroit où il a été cloné. Un même constat garde donc le même
identifiant d'un scan à l'autre, ce qui permet de comparer deux scans et de
reconnaître un faux positif déjà trié.

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

Deux moteurs différents qui signalent la même ligne du même fichier ne font
aussi qu'un constat. semgrep et gosec relèvent souvent le même appel
(`dangerous-exec-command` et `G204` sur un `exec.Command`), sous deux CWE
voisines. Le plus grave reste, et garde le titre, les moteurs et les CWE de
l'autre. Deux règles du même moteur sur la même ligne restent deux constats.
Le titre d'un constat semgrep garde la première phrase du message, le reste
est dans la description.

Chaque constat sort en statut `review` et `declared=false`. L'analyse statique
produit des **candidats**, pas des verdicts: confirmer une faille se fait sur
une instance locale montée soi-même, et la déclarer passe par une divulgation
coordonnée (GitHub Security Advisory). L'outil trie, l'opérateur décide.

### Préparer un signalement

`-advisory` lit un rapport écrit par `-scan-json`. Sans autre option, il liste
les constats qui peuvent devenir un signalement, en laissant de côté ceux qui
décrivent le scan lui-même (moteur absent, en panne). Avec `-finding`, il
prépare le brouillon d'un constat, dans la forme d'un GitHub Security Advisory.

```bash
quaero -scan owner/repo -scan-json rapport.json
quaero -advisory rapport.json
quaero -advisory rapport.json -finding <identifiant> -advisory-out brouillon.md
```

Le brouillon reprend ce que le scan sait: le dépôt, le commit analysé, l'endroit
du code ou la dépendance, la règle, le moteur, les références (CWE, CVE, GHSA,
OSV) avec leur lien. Il laisse à remplir ce que seul l'opérateur peut établir,
la reproduction sur une instance locale montée soi-même, l'impact réel et le
correctif proposé. Le corps est en anglais, la langue commune des mainteneurs.
Une liste de contrôle en français l'ouvre, en commentaire, à retirer avant
l'envoi: confirmer, vérifier que la faille n'est pas déjà connue, trouver le
canal privé du dépôt (onglet Security ou `SECURITY.md`), ne rien publier avant
le correctif. Pour une vulnérabilité de dépendance déjà publique, elle rappelle
de vérifier que le projet est réellement touché, sans quoi une simple mise à
jour suffit.

Quaero n'envoie rien. Le brouillon est écrit en `0600`, puisqu'il décrit une
faille encore non corrigée.

Ctrl+C pendant `-scan owner/repo` arrête les moteurs, efface le clone et
n'écrit aucun rapport. Des moteurs coupés en route passeraient pour un dépôt
vérifié. Un moteur arrêté l'est avec tout ce qu'il a lancé (groupe de
processus sous Linux et macOS, `taskkill /T` sous Windows), pour qu'aucun
sous-processus ne continue seul ni ne garde le clone ouvert. Un clone resté
d'une exécution précédente est signalé au démarrage de l'interface.

### Depuis l'interface

L'onglet « auditer » fait la même chose que `-scan`, sans terminal. On nomme
un dépôt GitHub (`owner/repo` ou une URL github.com), que Quaero clone,
analyse avec l'environnement durci des dépôts tiers, puis efface. On peut
aussi nommer le chemin complet d'un dossier de la machine, lu sur place. Le
lien « auditer » d'un résultat de recherche remplit le champ sans rien lancer.
Lancer reste un geste à part.

- Un dépôt github.com, public ou privé (voir plus haut), ou un dossier nommé
  par son chemin complet. Un chemin relatif dépendrait du dossier où Quaero a
  été lancé, il est refusé, comme une racine de disque.
- Une analyse à la fois, annulable. Une seconde demande est refusée, pas mise
  en file. Fermer l'onglet ne l'arrête pas, le bouton « annuler » si, et
  Ctrl+C dans le terminal l'arrête et efface son clone avant de quitter.
- Les moteurs s'affichent avec leur durée, ou absents, ou en échec. Un rapport
  sans constat ne vaut que si les moteurs ont tourné, et la page le dit.
- Les vulnérabilités publiées d'une même dépendance tiennent sur une seule
  ligne, avec leur nombre. Elles sont déjà connues, la réponse est une mise à
  jour par une PR ordinaire, pas un signalement privé. Quand govulncheck trouve
  un appel au code fautif, la ligne le dit.
- Deux filtres, gravité et type (code, dépendances), réduisent la liste sans
  relancer l'analyse.
- À la place du quota de recherche, un encart dit ce que l'audit permet. Une
  analyse à la fois, 15 minutes au plus par moteur. L'audit ne prend rien sur
  le quota de l'API GitHub, le clone passe par git.
- Un échec se dit en une ligne, selon le cas. Dépôt privé ou inexistant, jeton
  sans accès au dépôt, jeton refusé, github.com injoignable ou git absent.
- « préparer le signalement » ouvre le brouillon d'un constat sous celui-ci,
  le même que `-advisory`, à copier ou à enregistrer en `.md`, avec le lien
  du formulaire de signalement privé du dépôt sur GitHub. Ce formulaire
  n'existe que si le mainteneur l'a activé, sinon `SECURITY.md` dit où écrire.

### Rapports enregistrés

Une analyse finie reste en mémoire jusqu'à la suivante. Pour la garder, clique
« enregistrer » sous son titre. Elle va dans `~/.quaero/rapports`, soit
`%USERPROFILE%\.quaero\rapports` sous Windows, un fichier JSON par analyse au
même format que `-scan-json`. Sous Linux et macOS, le dossier et les fichiers
ne sont lisibles que par toi. Rien n'est écrit sans ce clic.
Quand Quaero écoute sur toutes les interfaces (`-addr 0.0.0.0:7777`), les
rapports ne sont ni gardés ni servis, comme les dossiers locaux. Ils peuvent
citer du code privé.

- « rapports enregistrés », sous le champ, les liste de l'analyse la plus
  récente à la plus ancienne, avec sa date, sa cible et son nombre de
  constats.
- Un clic sur une ligne rouvre le rapport, sans réseau ni nouvelle analyse.
  Une étiquette au-dessus du titre le distingue de l'analyse en cours, et
  « fermer » y revient. Les filtres et « préparer le signalement » marchent
  comme après une analyse.
- « supprimer » efface le fichier, après confirmation.
- « importer un rapport » range un fichier écrit par `-scan-json`, sur cette
  machine ou une autre, jusqu'à 20 Mo et 50 000 constats. Un fichier déposé
  n'importe où sur la page fait de même, plusieurs à la fois si besoin. Seul
  leur format est vérifié, leur contenu reste une donnée affichée. Les
  rapports du dossier sont déjà dans la liste. Un rapport déjà rangé n'est
  pas rangé deux fois, il est rouvert avec l'étiquette « déjà dans la liste ».
  Le navigateur ne laisse pas une page choisir le dossier où s'ouvre le
  sélecteur de fichiers.
- Le fichier d'un rapport enregistré se relit tel quel avec `-advisory`.

Un rapport décrit des failles pas encore corrigées. Garde-le en privé, comme
les brouillons. Ceux-ci se préparent à la demande, en mémoire, et ne sont pas
enregistrés. Rien n'est envoyé.

La page ne parle qu'à Quaero, sur ta machine, et marche sans réseau tant que
Quaero tourne. S'il est arrêté, une ligne en tête de page le dit. Relancé, il
reprend dans le même onglet (voir « Session et contrôle de l'hôte »).

## Structure

```
internal/intent/    lecture de la phrase vers des facettes
internal/github/    appel de l'API de recherche, sans jugement
internal/rank/      pertinence et santé, deux jugements distincts
internal/audit/     santé des dépôts d'une requête, vers le schéma de constat
internal/codescan/  audit de code (govulncheck, gosec, semgrep, osv-scanner)
internal/advisory/  brouillon de signalement privé à partir d'un constat
internal/reports/   rapports enregistrés sur la machine, import et relecture
internal/repo/      lecture des références de dépôt GitHub, partagée
internal/proctree/  arrêt d'un processus et de tout ce qu'il a lancé
internal/finding/   schéma de constat partagé par la suite
internal/webui/     serveur HTTP, cache des pages, analyses, page et polices
scripts/polices.py  récupération des polices de l'interface
cmd/quaero/         point d'entrée
```

## Développement

```bash
go vet ./...
go test ./... -count=1
```
