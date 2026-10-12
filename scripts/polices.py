# Copyright (c) 2026 Terry Passave. All rights reserved.
# Proprietary and confidential. Unauthorized use is prohibited.

"""Recupere les polices de l'interface et les range dans internal/webui/fonts.

L'interface est servie en local, sous une politique de contenu qui interdit
toute ressource exterieure. Les polices sont donc embarquees dans le binaire,
et ce script est la seule etape qui touche le reseau: il tourne une fois, a la
main, et son resultat est versionne.

Trois fichiers, tous sous licence SIL OFL 1.1:
  jetbrains-mono.woff2   interface, graisses 400 a 800, jeu latin
  syne.woff2             grands titres, graisses 700 et 800, jeu latin
  archivo-quaero.woff2   logotype, Archivo large et extra-gras, lettres de "quaero" seulement

Usage, depuis la racine du depot:
  python scripts/polices.py

Bibliotheque standard uniquement, rien a installer.
"""

import hashlib
import pathlib
import re
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "internal" / "webui" / "fonts"

# Google ne sert du woff2 qu'a un navigateur qui sait le lire.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

FONTS = [
    # (fichier, famille et axes au format css2, texte a garder ou None, dossier ofl)
    ("jetbrains-mono.woff2", "JetBrains Mono:wght@400..800", None, "jetbrainsmono"),
    ("syne.woff2", "Syne:wght@700..800", None, "syne"),
    ("archivo-quaero.woff2", "Archivo:wdth,wght@125,800", "quaero", "archivo"),
]

LICENSES = {
    "jetbrainsmono": "OFL-JetBrainsMono.txt",
    "syne": "OFL-Syne.txt",
    "archivo": "OFL-Archivo.txt",
}

FACE = re.compile(r"(?:/\*\s*([\w-]+)\s*\*/\s*)?@font-face\s*\{([^}]*)\}")
WOFF2 = re.compile(r"url\((https://[^)]+)\)\s*format\(['\"]woff2['\"]\)")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def woff2_url(family, text):
    params = {"family": family, "display": "swap"}
    if text:
        params["text"] = text
    # Les deux-points, arobases et virgules de la syntaxe css2 restent lisibles.
    query = urllib.parse.urlencode(params, safe=":@,.")
    css = get("https://fonts.googleapis.com/css2?" + query).decode("utf-8")
    faces = FACE.findall(css)
    if not faces:
        raise SystemExit(f"{family}: aucune declaration @font-face dans la reponse")
    # Une demande avec texte rend un seul bloc sans jeu nomme. Sinon on garde le
    # jeu latin, qui couvre le francais (accents, cedille, oe).
    chosen = faces[0][1]
    if any(subset for subset, _ in faces):
        latin = [body for subset, body in faces if subset == "latin"]
        if not latin:
            raise SystemExit(f"{family}: pas de jeu latin dans la reponse")
        chosen = latin[0]
    m = WOFF2.search(chosen)
    if not m:
        raise SystemExit(f"{family}: pas de woff2 dans la reponse, le serveur a peut-etre change de format")
    return m.group(1)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sums = []
    for name, family, text, ofl in FONTS:
        url = woff2_url(family, text)
        data = get(url)
        if not data.startswith(b"wOF2"):
            raise SystemExit(f"{name}: le fichier recu n'est pas du woff2")
        (OUT / name).write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
        print(f"{name:24} {len(data):>7} octets")

    for ofl, filename in LICENSES.items():
        data = get(f"https://raw.githubusercontent.com/google/fonts/main/ofl/{ofl}/OFL.txt")
        if b"SIL OPEN FONT LICENSE" not in data.upper():
            raise SystemExit(f"{filename}: la licence recue n'est pas l'OFL")
        (OUT / filename).write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {filename}")
        print(f"{filename:24} {len(data):>7} octets")

    (OUT / "SHA256SUMS").write_bytes(("\n".join(sums) + "\n").encode("utf-8"))
    print(f"\npolices rangees dans {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        main()
    except OSError as err:
        sys.exit(f"telechargement impossible: {err}")
