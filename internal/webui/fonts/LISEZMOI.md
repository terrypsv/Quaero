# Polices de l'interface

Fichiers produits par `python scripts/polices.py`, à relancer seulement pour
changer de police ou de version. Ils sont embarqués dans le binaire
(`go:embed`), parce que la politique de contenu de l'interface n'autorise
aucune ressource extérieure.

| Fichier | Usage | Licence |
|---|---|---|
| `archivo.woff2` | texte, titres et logotype | `OFL-Archivo.txt` |
| `jetbrains-mono.woff2` | requêtes et chemins | `OFL-JetBrainsMono.txt` |

Les deux polices sont sous licence SIL Open Font License 1.1, qui autorise
leur distribution avec un logiciel tant que la licence les accompagne.
`SHA256SUMS` garde l'empreinte de chaque fichier tel qu'il a été récupéré.
Seuls les `.woff2` sont servis par l'interface.
