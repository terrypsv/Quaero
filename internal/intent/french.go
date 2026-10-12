// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"

	"github.com/terrypsv/Quaero/internal/model"
)

// French reecrit une intention pour chercher les mots tels qu'ils ont ete
// tapes, sans traduction. C'est la recherche des projets decrits en francais:
// la traduction vers l'anglais, utile partout ailleurs, les rendrait
// introuvables.
//
// Les termes viennent de la lecture mot a mot. Une expression de plusieurs
// mots ("ligne de commande") part entre guillemets, pour etre cherchee telle
// quelle. Les mots generiques restent ecartes, pour la meme raison qu'en
// anglais: un seul mot absent des descriptions vide tout le resultat. Sans
// terme a reprendre ("du rust"), l'intention est rendue telle quelle.
func French(in model.Intent) model.Intent {
	out := in
	out.Topics = nil
	out.Terms = nil
	out.Reading = append([]model.Segment(nil), in.Reading...)
	seen := map[string]bool{}
	for i, s := range out.Reading {
		if s.Role != model.RoleTerm {
			continue
		}
		word := strings.ToLower(strings.TrimSpace(s.Text))
		if strings.ContainsAny(word, " \t") {
			word = `"` + strings.Join(strings.Fields(word), " ") + `"`
		}
		out.Reading[i].Value = word
		// Quatre termes au plus, comme en anglais: au-dela, les chances qu'un
		// meme depot les contienne tous s'effondrent.
		if seen[word] || len(out.Terms) >= 4 {
			continue
		}
		seen[word] = true
		out.Terms = append(out.Terms, word)
	}
	if len(out.Terms) == 0 {
		return in
	}
	return out
}
