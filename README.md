<img width="485" height="184" alt="ascii-art-text" src="https://github.com/user-attachments/assets/f68fb629-efe8-459d-889e-611113698594" />


# Quaero

Recherche de depots GitHub par intention, avec un verdict sur la sante de ce
qu'on trouve.

La recherche native de GitHub attend un langage de requete: qualificateurs,
deux-points, operateurs de comparaison. Qui le connait trouve tout, qui ne le
connait pas obtient une correspondance de mots-clefs sur un README et un mur de
forks. Le manque n'est pas dans l'index, il est dans l'interface.

Quaero lit une phrase. `une bibliotheque go pour parser du yaml, encore
maintenue` devient des termes, un langage et une fenetre de fraicheur, et
l'outil affiche ce qu'il a compris pour qu'une phrase mal lue puisse etre
corrigee plutot que subie.

**Logiciel proprietaire.** Voir `LICENSE`.

## Ce qu'il ajoute vraiment

Chercher une bibliotheque pose deux questions, pas une. La premiere est
"est-ce que ca fait ce dont j'ai besoin". La seconde est "est-ce que je peux en
dependre", et c'est celle que l'interface native n'aide pas a trancher.

Un compteur d'etoiles dit qu'un projet a ete utile, pas qu'il l'est encore. Une
bibliotheque a quarante mille etoiles sans commit depuis trois ans est une plus
mauvaise dependance qu'une obscure poussee la semaine derniere, et rien dans la
liste par defaut ne permet de les distinguer.

Chaque resultat porte donc un verdict de sante:

| Niveau | Signification |
|--------|---------------|
| sain | pousse dans les trois derniers mois |
| calme | moins d'un an, ce qui peut etre normal pour une bibliotheque finie |
| dormant | entre un et deux ans sans envoi |
| abandonne | plus de deux ans, considerer le projet comme arrete |
| archive | archive par son proprietaire, il ne recevra plus de correctif |

Un depot dont la date d'envoi est absente n'est jamais declare sain: affirmer
la sante a partir d'une donnee manquante serait pire que ne rien dire.

## La phrase est en francais, la requete part en anglais

GitHub indexe des noms de depots, des descriptions et des README, et ils sont
massivement en anglais. Une phrase tapee en francais doit donc franchir la
barriere de langue avant de devenir une requete, sinon elle ne correspond a
rien.

Deux mecanismes s'en chargent, et le premier compte plus que le second.

Les mots qui decrivent le *genre* de la chose cherchee sont ecartes.
"bibliotheque", "outil", "module": personne n'ecrit "library" dans la
description de sa bibliotheque. Comme GitHub combine les termes en ET, un seul
mot qui ne correspond a rien vide tout le resultat: garder "bibliotheque"
suffisait a ne rien trouver.

Le vocabulaire technique courant est traduit, y compris les expressions qui
n'ont de sens qu'en groupe. "ligne de commande" devient `cli`, "base de
donnees" devient `database` et non "database data", qui ramenerait la moitie
de GitHub.

## Quand rien ne correspond

Une page vide est la pire reponse possible: elle ne distingue pas "ca n'existe
pas" de "la requete etait trop serree". Quaero desserre alors les contraintes
une par une, de la moins signifiante a la plus signifiante, et dit ce qu'il a
lache.

L'ordre est deliberé. La fraicheur et la popularite cedent en premier, parce
que la phrase les a rarement exigees. Les termes cedent en dernier, parce
qu'ils sont la question elle-meme.

Un resultat trouve apres desserrage reste un resultat. Un resultat trouve en
silence apres desserrage serait un mensonge.

## Installation

```bash
go build -o quaero ./cmd/quaero
```

Un jeton GitHub est obligatoire. Sans lui, l'API limite a 60 requetes par
heure, ce qu'une seule session epuise. Le jeton n'a besoin d'aucune permission:
la recherche publique n'en demande pas.

Le plus simple est de l'enregistrer une fois:

```bash
./quaero -save-token <jeton>
./quaero
```

Il est ecrit dans `~/.quaero/config.json`, en lecture reservee au proprietaire.
`./quaero -forget-token` l'efface.

Pour une session seulement, la variable d'environnement fonctionne toujours et
prime sur le fichier:

```bash
export GITHUB_TOKEN=...        # bash
$env:GITHUB_TOKEN="..."        # PowerShell
```

Le quota restant est affiche a chaque recherche, pour qu'une coupure imminente
se voie venir plutot que de surprendre.

L'interface est sur `http://127.0.0.1:7777`. L'ecoute est sur la boucle locale
par defaut, parce que le processus porte un jeton: un outil expose sur toutes
les interfaces par defaut est un outil qui laisse fuir ce jeton la premiere
fois qu'il tourne sur un reseau qui n'est pas le sien.

## Ce que la phrase peut exprimer

| Ce qu'on ecrit | Ce qui est compris |
|----------------|--------------------|
| `en go`, `du rust`, `python` | facette de langage |
| `maintenu`, `encore actif`, `recent` | fenetre de fraicheur |
| `populaire`, `tres utilise` | plancher d'etoiles |
| `au moins 2000 etoiles` | plancher explicite, prioritaire |
| `y compris les forks` | annule l'exclusion par defaut |
| `y compris archives` | annule l'exclusion par defaut |

Les forks et les depots archives sont ecartes par defaut: ils forment
l'essentiel du bruit dans les resultats natifs, et qui cherche une
bibliotheque a utiliser n'en veut presque jamais.

## Trier autrement

La bonne reponse n'est pas la meme question pour tout le monde. Cinq
ordonnancements sont disponibles depuis l'interface:

| Mode | Ce qu'il remonte |
|------|------------------|
| pertinence | equilibre entre precision des termes, langage et sante |
| populaire | les projets largement adoptes d'abord |
| niche | les petits projets precis, entre 20 et 2000 etoiles, que la popularite enterre |
| recent | par date du dernier envoi |
| sante | les depots sur lesquels on peut le plus surement s'appuyer |

Le mode niche existe parce qu'un outil qui ne montre jamais que la reponse
celebre est un outil incapable de trouver la reponse specifique. Le plancher de
vingt etoiles est deliberé: en dessous, un projet n'est pas niche, il est
simplement non eprouve.

## Pagination

GitHub ne restitue que mille resultats, quel que soit le nombre de
correspondances. Une recherche qui annonce onze mille depots n'en rend donc
accessibles que mille, et l'interface affiche les deux chiffres. Promettre des
pages qui reviendraient vides serait pire que d'annoncer la limite.

Cliquer un langage ou un sujet l'ajoute a la phrase et relance la recherche:
c'est le raffinement qu'on veut faire apres avoir vu une premiere page.

## Le classement

La pertinence privilegie la precision sur la popularite. Un terme dans le nom
du depot vaut bien plus que le meme terme noye dans une description, parce que
nommer son projet d'apres un concept signale generalement qu'on a construit ce
concept.

Les etoiles departagent, elles ne decident pas: leur contribution est
logarithmique, pour qu'un projet a cinquante mille etoiles n'efface pas le
champ.

Chaque resultat indique ce qui lui a valu sa place. Un classement que personne
ne peut interroger est un classement auquel personne ne devrait se fier.

## Structure

```
internal/intent/    lecture de la phrase vers des facettes
internal/github/    appel de l'API de recherche, sans jugement
internal/rank/      pertinence et sante, deux jugements distincts
internal/webui/     serveur HTTP et page embarquee
cmd/quaero/         point d'entree
```

## Developpement

```bash
go vet ./...
go test ./... -count=1
```
