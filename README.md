<p align="center">
  <img src="assets/quaero.svg" alt="Quaero. Trouver un dépôt, savoir s'il tient, auditer son code." width="100%">
</p>

Quaero aide à choisir du code open source et à le rendre plus sûr. Tu décris
ce que tu cherches avec tes mots, il trouve les dépôts GitHub qui
correspondent et dit lesquels sont encore entretenus. Il peut ensuite analyser
le code d'un dépôt pour y repérer des failles, et préparer un signalement
privé pour ses mainteneurs.

## Ce qu'il fait

**Chercher.** Une phrase suffit, en français ou en anglais, par exemple « un
scanner de ports en go, encore maintenu ». Quaero la traduit en requête GitHub
et montre ce qu'il a compris, mot par mot.

**Juger.** Chaque dépôt reçoit un verdict, d'actif à archivé. Les étoiles
disent qu'un projet a été utile, pas qu'il l'est encore.

**Auditer.** Quaero passe le code au crible d'outils d'analyse reconnus
(semgrep, osv-scanner, govulncheck, gosec) et trie ce qu'ils trouvent. D'un
côté les failles possibles dans le code, de l'autre les dépendances à mettre à
jour.

**Signaler.** Pour une faille confirmée, il prépare un brouillon au format
GitHub Security Advisory. Il n'envoie rien. C'est toi qui vérifies, puis qui
l'envoies au mainteneur.

## Ses règles

- Il lit du code, il n'attaque rien. Aucun système en service n'est sondé.
- Une faille se confirme sur une copie installée chez soi, jamais chez
  quelqu'un d'autre.
- Elle se signale en privé, et rien n'est publié avant le correctif.
- Pas de scan de masse. Chaque cible est choisie à la main.
- Il n'écrit jamais dans un dépôt et ne transmet rien de ce qu'il analyse.

## Démarrer

1. Télécharge le binaire de ta plateforme dans les
   [Releases](https://github.com/terrypsv/Quaero/releases), ou compile-le avec
   `go build -o quaero ./cmd/quaero`.
2. Lance `quaero`. L'interface s'ouvre dans ton navigateur.
3. Facultatif. Sans jeton, GitHub limite la recherche à 10 requêtes par
   minute. Un jeton sans aucune permission en donne 30, à enregistrer une fois
   avec `quaero -save-token <jeton>`.

Pour auditer, il faut git et les outils d'analyse. Un outil absent est signalé
dans le rapport, jamais ignoré en silence.

```text
pipx install semgrep
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

## Utilisation

L'interface a deux onglets. **rechercher** trouve des dépôts, les classe et
aide à resserrer une liste trop longue. **auditer** analyse un dépôt GitHub ou
un dossier de ta machine, filtre les constats par gravité et prépare les
signalements. Coche « Enregistrer le rapport » avant de lancer, l'analyse
reste sur ta machine et se rouvre plus tard sans réseau. Un rapport
`-scan-json` s'importe, ou se dépose sur la page, pour préparer ses
signalements depuis l'interface. Relancer Quaero reprend l'onglet déjà ouvert.

Le tri se fait sans modèle de langage. Les constats dans des tests, des
exemples ou du code généré sont rangés à part. Chaque constat se marque
confirmé, faux positif ou signalé, et la décision revient avec les analyses
suivantes du même dépôt.

La même chose existe en ligne de commande.

```text
quaero -scan owner/repo                      audite un dépôt GitHub
quaero -scan C:\chemin\du\projet             audite un dossier
quaero -scan owner/repo -scan-json r.json    garde le rapport
quaero -scan owner/repo -scan-timeout 30m    délai maximal par moteur (15 min par défaut)
quaero -advisory r.json -finding <id>        prépare un brouillon de signalement
quaero -advisory r.json -finding <id> -advisory-out brouillon.md
                                             écrit le brouillon dans un fichier
```

`-audit` note d'un coup la santé des dépôts trouvés pour une phrase, sans
ouvrir l'interface. `-audit-limit` fixe leur nombre (30 par défaut) et
`-audit-json` écrit le rapport au schéma de constat partagé, lisible par Acta.
Un dépôt abandonné ou archivé ressort en échec (`fail`), un dépôt dormant ou
sans licence est à vérifier (`review`), les autres passent.

```text
quaero -audit "scanner de ports en go"                    note 30 dépôts
quaero -audit "scanner de ports en go" -audit-limit 10 -audit-json sante.json
```

**Autres options.** `-addr` change l'adresse d'écoute (127.0.0.1:7777 par
défaut), `-no-browser` n'ouvre pas le navigateur, `-forget-token` oublie le
jeton enregistré, `-version` affiche la version. `quaero -h` donne la liste
complète.

**Codes de sortie.** `0` quand la commande va au bout, `2` en cas d'erreur ou
d'interruption. `-audit` rend `1` si au moins un dépôt est en échec. `-scan`
ne rend jamais `1`, même quand il relève des failles possibles. Tous ses
constats sortent à vérifier (`review`), parce qu'un outil d'analyse propose
des candidats et ne confirme rien. C'est le rapport qu'il faut lire, pas le
code de sortie.

## Dépôts privés

Un dépôt privé s'audite par son dossier, s'il est déjà cloné, ou par son nom
avec un jeton qui peut le lire. Quaero essaie toujours d'abord sans
identifiant, et ne sort le jeton que si GitHub le demande. Le code ne quitte
pas ta machine. Seuls le nom et la version des dépendances partent vers la
base publique OSV.

## En savoir plus

Le [guide](docs/GUIDE.md) détaille la lecture de la phrase, le classement, les
outils d'analyse et la protection de l'interface. La
[feuille de route](docs/ROADMAP.md) dit ce qui vient ensuite.

## Licence

Logiciel propriétaire, tous droits réservés, voir [LICENSE](LICENSE).
