// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"

	"github.com/terrypsv/Quaero/internal/model"
)

// A Strategy is one way of asking the same question.
//
// A single query is a single hypothesis about where the answer lives. Asking
// GitHub for "yaml parser" searches names, descriptions and READMEs at once
// and ranks them together, which means a project literally named yaml-parser
// competes on equal footing with one that merely mentions the words in a
// paragraph of documentation.
//
// Running the question several ways instead, each restricted to a different
// part of the repository, produces something a single query cannot: agreement.
// A project returned by the name search *and* the topic search *and* the
// description search is almost certainly the right answer, and that agreement
// is measurable. It is a far stronger signal than any weighting applied to one
// undifferentiated list.
//
// The cost is one API call per strategy. That is the trade being made: quota
// for precision.
type Strategy struct {
	// Query is what gets sent.
	Query string
	// Label names the hypothesis, for display and for explaining a ranking.
	Label string
	// Weight is how much a match here says about relevance. A term in the
	// repository name is a deliberate act by its author; a term in the README
	// may be an aside.
	Weight float64
}

// Strategies returns the ways of asking, from most to least precise.
//
// The `in:` qualifiers are what make this possible: they restrict matching to
// a named field instead of the default which searches everything at once.
func Strategies(in model.Intent, deep bool) []Strategy {
	terms := strings.Join(in.Terms, " ")
	if strings.TrimSpace(terms) == "" {
		return nil
	}

	base := Query(in)

	// The default single query stays first: it is the balanced view, and on a
	// quick search it is the only one run.
	out := []Strategy{
		{Query: base, Label: "recherche generale", Weight: 1},
	}
	if !deep {
		return out
	}

	// Name only. The strongest signal available: naming a project after a
	// concept is a claim to be that concept.
	out = append(out, Strategy{
		Query:  withQualifier(in, "in:name"),
		Label:  "nom du depot",
		Weight: 3,
	})

	// Description only. Weaker than the name, much stronger than a README
	// mention, because a description is written to answer "what is this".
	out = append(out, Strategy{
		Query:  withQualifier(in, "in:description"),
		Label:  "description",
		Weight: 2,
	})

	// Topics are curated by maintainers rather than extracted from prose, so
	// a topic match is an explicit statement of what the project is for.
	for _, term := range in.Terms {
		if len(term) < 3 {
			continue
		}
		topical := in
		topical.Terms = nil
		topical.Topics = []string{term}
		out = append(out, Strategy{
			Query:  Query(topical),
			Label:  "sujet " + term,
			Weight: 2.5,
		})
		// One topic query is enough: each additional one costs a call and
		// topics rarely disagree with each other.
		break
	}

	// The exact phrase, when there is more than one term. Quoting turns an
	// AND of scattered words into a demand for the words together, which is
	// what someone means by "a yaml parser" and not "yaml, and separately,
	// parsing".
	if len(in.Terms) > 1 {
		quoted := in
		quoted.Terms = []string{`"` + terms + `"`}
		out = append(out, Strategy{
			Query:  Query(quoted),
			Label:  "expression exacte",
			Weight: 3.5,
		})
	}

	return out
}

// withQualifier rebuilds a query with an `in:` restriction appended.
func withQualifier(in model.Intent, qualifier string) string {
	// Topics are dropped: combining a topic facet with an in:name restriction
	// demands both, which is stricter than either and finds almost nothing.
	stripped := in
	stripped.Topics = nil
	return Query(stripped) + " " + qualifier
}
