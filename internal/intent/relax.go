// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"

	"github.com/terrypsv/Quaero/internal/model"
)

// Relaxation is one step down from a query that found nothing.
//
// An empty result page is the worst answer a search tool can give, because it
// is indistinguishable from "this does not exist". Almost always the thing
// exists and the query was one constraint too tight: a facet the phrase only
// implied, or a fourth term that no single repository happens to carry.
//
// Rather than leave the user to guess which word to delete, the tool takes the
// constraints off one at a time, in increasing order of how much meaning they
// carry, and says what it removed. A result found after relaxation is still a
// result; a result found silently after relaxation would be a lie.
type Relaxation struct {
	Intent model.Intent
	Query  string
	// Reason names, in plain words, what was given up to get here.
	Reason string
}

// Ladder returns the sequence of progressively looser queries to try after the
// original one came back empty.
//
// The order is deliberate. Recency and popularity go first because the phrase
// rarely insisted on them: "maintenue" is a preference, not a requirement.
// Terms go last because they are the question itself, and a search that has
// dropped the question is no longer answering it.
func Ladder(in model.Intent) []Relaxation {
	var steps []Relaxation

	// A step whose query is the one already tried costs a call and says
	// something false. It happens when a criterion read from the phrase is
	// also held by a filter the user chose: relaxing the first leaves the
	// second, and the query does not move.
	last := Query(in)
	add := func(current model.Intent, reason string) {
		q := Query(current)
		if q == last {
			return
		}
		last = q
		steps = append(steps, Relaxation{Intent: current, Query: q, Reason: reason})
	}

	current := in

	if current.PushedWithinDays > 0 {
		current.PushedWithinDays = 0
		add(current, "sans la contrainte de fraîcheur")
	}

	if current.MinStars > 0 {
		current.MinStars = 0
		add(current, "sans le minimum d'étoiles")
	}

	// Topics are a guess made from the shape of a word, not something the user
	// asked for, so they cost nothing to give up. Topics the user clicked live
	// in Filters and are never touched here.
	if len(current.Topics) > 0 {
		current.Topics = nil
		add(current, "sans le filtre par sujet")
	}

	// Dropping terms from the end: the first words of a phrase usually carry
	// the subject, the last ones qualify it.
	for len(current.Terms) > 1 {
		dropped := current.Terms[len(current.Terms)-1]
		current.Terms = current.Terms[:len(current.Terms)-1]
		add(current, "sans le mot-clé « "+strings.Trim(dropped, `"`)+" »")
	}

	// Last resort: the language qualifier alone with the remaining term. If
	// this finds nothing either, the thing genuinely is not there.
	if (current.Language != "" || current.Filters.Language != "") && len(current.Terms) == 1 {
		loose := current
		loose.ExcludeForks = false
		add(loose, "forks inclus")
	}

	return steps
}

// Describe renders a relaxation reason for display.
func Describe(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return "Rien trouvé avec la demande exacte. Résultats obtenus " +
		strings.Join(reasons, ", puis ") + "."
}
