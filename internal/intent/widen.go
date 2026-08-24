// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import "github.com/terrypsv/Quaero/internal/model"

// Widen returns the additional queries to run so that non-English communities
// are not excluded from the answer.
//
// The obvious approach, putting every language variant into one query, does
// not work: GitHub combines terms with AND, so a query holding both "parser"
// and "解析" matches only repositories containing both, which is almost none.
// The variants therefore have to be separate queries whose results are merged.
//
// That costs one API call per variant, which is why widening is a choice
// rather than the default. With a personal token the budget is five thousand
// calls an hour, so a handful of extra calls per search is affordable; making
// it automatic would quietly multiply everyone's consumption by five.
//
// Only the most distinctive term is substituted, not all of them. Replacing
// two terms at once would produce a query where a Chinese word and a Russian
// word must both appear, which describes no repository on earth.
func Widen(in model.Intent, maxQueries int) []string {
	if maxQueries <= 0 {
		return nil
	}

	// The head term is the one worth translating: the first content word
	// usually names the subject, the ones after it qualify.
	var head string
	var headIndex int
	for i, t := range in.Terms {
		if len(multilingual[t]) > 0 {
			head, headIndex = t, i
			break
		}
	}
	if head == "" {
		return nil
	}

	var out []string
	for _, variant := range multilingual[head] {
		if len(out) >= maxQueries {
			break
		}
		alt := in
		alt.Terms = append([]string(nil), in.Terms...)
		alt.Terms[headIndex] = variant
		// A description written in another language rarely carries the
		// English topic names, so the topic facet is dropped: keeping it would
		// make the widened query stricter than the original, which defeats the
		// purpose.
		alt.Topics = nil
		out = append(out, Query(alt))
	}
	return out
}
