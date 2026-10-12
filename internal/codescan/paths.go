// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"path/filepath"
	"strings"
)

// relTo rend p relatif a root, en barres obliques, quand p est sous root.
//
// Les moteurs rendent des chemins absolus. Ils changent d'une machine a
// l'autre, et a chaque scan d'un depot clone, puisque le clone tombe dans un
// dossier temporaire au nom aleatoire. Un identifiant de constat construit sur
// un tel chemin ne designerait jamais deux fois le meme constat: impossible de
// comparer deux scans du meme code, ni de reconnaitre un faux positif deja
// trie. Le chemin dans le depot, lui, ne bouge pas.
func relTo(root, p string) string {
	if root == "" || p == "" {
		return p
	}
	if !filepath.IsAbs(p) {
		return filepath.ToSlash(p)
	}
	if rel, err := filepath.Rel(root, p); err == nil && rel != "." &&
		!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
		return filepath.ToSlash(rel)
	}
	// Le moteur peut ecrire la racine autrement que nous: nom court 8.3 sous
	// Windows (TERRYP~1), lien /var vers /private/var sous macOS. Le dernier
	// element de la racine suffit alors a couper, et il est unique pour un
	// dossier temporaire.
	slash := filepath.ToSlash(p)
	base := filepath.Base(filepath.Clean(root))
	if base != "" && base != "." && base != "/" && base != `\` {
		marker := "/" + base + "/"
		if i := strings.Index(slash, marker); i >= 0 {
			return slash[i+len(marker):]
		}
	}
	return p
}
