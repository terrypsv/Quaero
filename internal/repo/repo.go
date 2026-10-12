// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package repo lit les references de depot GitHub, pour la ligne de commande
// et pour l'interface: les deux doivent accepter et refuser exactement les
// memes cibles.
//
// Nommer la cible reste un acte humain. Ce paquet ne cherche rien, il dit
// seulement si ce qu'on lui donne designe un depot public sur github.com.
// Un autre hote ou un depot prive se clone a la main, puis s'analyse avec
// `-scan <chemin>`.
package repo

import (
	"regexp"
	"strings"
)

// Ref est une reference de depot GitHub reduite a owner/nom.
type Ref struct {
	Owner string
	Name  string
}

// String rend owner/nom.
func (r Ref) String() string { return r.Owner + "/" + r.Name }

// URL rend la page du depot.
func (r Ref) URL() string { return "https://github.com/" + r.String() }

// CloneURL rend l'adresse de clone, en HTTPS et en lecture publique.
func (r Ref) CloneURL() string { return r.URL() + ".git" }

// ReportURL rend le formulaire de signalement prive du depot. Il n'existe que
// si le mainteneur a active le signalement prive; sinon, SECURITY.md dit ou
// ecrire.
func (r Ref) ReportURL() string { return r.URL() + "/security/advisories/new" }

var (
	// Login GitHub: lettres, chiffres et tirets simples, 39 au plus.
	ownerPat = `[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?`
	// Nom de depot GitHub: lettres, chiffres, point, tiret, souligne.
	namePat = `[A-Za-z0-9._-]{1,100}`
	// Le nom d'hote ne tient pas compte de la casse, le chemin si.
	urlRe  = regexp.MustCompile(`^(?i:(?:https?://)?(?:www\.)?github\.com)/(` + ownerPat + `)/(` + namePat + `)$`)
	sshRe  = regexp.MustCompile(`^git@(?i:github\.com):(` + ownerPat + `)/(` + namePat + `)$`)
	bareRe = regexp.MustCompile(`^(` + ownerPat + `)/(` + namePat + `)$`)
)

// Parse lit une reference de depot GitHub sous ses formes usuelles
// (owner/repo, URL https, URL git@), ou dit qu'elle n'en est pas une.
func Parse(s string) (Ref, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	for _, re := range []*regexp.Regexp{urlRe, sshRe, bareRe} {
		if m := re.FindStringSubmatch(s); m != nil {
			name := m[2]
			// "." et ".." ne sont pas des depots, et un nom tout en points
			// n'ouvre pas de chemin.
			if strings.Trim(name, ".") == "" {
				return Ref{}, false
			}
			return Ref{Owner: m[1], Name: name}, true
		}
	}
	return Ref{}, false
}
