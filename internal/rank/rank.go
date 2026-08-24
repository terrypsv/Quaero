// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package rank reorders search results and rates whether a repository can be
// depended upon.
//
// Two judgements live here, and they are kept apart on purpose.
//
// Relevance answers "does this do what I asked". GitHub's own relevance is a
// reasonable first pass, but it is dominated by popularity: a famous project
// that mentions the term in passing outranks a small one that is exactly it.
// The reordering here weights where the term appears, not how many people
// starred it.
//
// Health answers "can I depend on this", which the native interface does not
// answer at all. Star counts say a project was useful once, not that it still
// is. A library with forty thousand stars and no commit in three years is a
// worse dependency than an obscure one pushed last week, and nothing in the
// default listing tells you which is which.
//
// Both judgements are explainable by construction: every point added is
// recorded as a reason. A ranking nobody can question is a ranking nobody
// should trust.
package rank

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/model"
)

// Health levels, from best to worst.
const (
	LevelHealthy   = "sain"
	LevelCalm      = "calme"
	LevelDormant   = "dormant"
	LevelAbandoned = "abandonne"
	LevelArchived  = "archive"
)

// now is swappable in tests: a health rating that changes with the calendar
// cannot be asserted otherwise.
var now = time.Now

// Rate fills the Health of a repository.
//
// The thresholds are blunt and stated rather than tuned. Six months of silence
// is not a defect in a finished library, so it is "calme", not a warning. Two
// years is a real signal, whatever the star count. And a repository that never
// had a push date is unknown, not healthy: claiming health from missing data
// is the failure mode this whole suite exists to avoid.
func Rate(r model.Repo) model.Health {
	h := model.Health{}

	if r.Stars > 0 {
		h.IssueRatio = float64(r.OpenIssues) / float64(r.Stars) * 100
	}

	if r.Archived {
		h.Level = LevelArchived
		h.Notes = append(h.Notes, "depot archive par son proprietaire, il ne recevra plus de correctif")
		return h
	}

	if r.PushedAt.IsZero() {
		h.Level = LevelDormant
		h.DaysSincePush = -1
		h.Notes = append(h.Notes, "date de dernier envoi inconnue, l'activite ne peut pas etre evaluee")
		return h
	}

	days := int(now().Sub(r.PushedAt).Hours() / 24)
	h.DaysSincePush = days

	switch {
	case days <= 90:
		h.Level = LevelHealthy
		h.Notes = append(h.Notes, fmt.Sprintf("dernier envoi il y a %s", humanDays(days)))
	case days <= 365:
		h.Level = LevelCalm
		h.Notes = append(h.Notes, fmt.Sprintf("dernier envoi il y a %s, ce qui peut etre normal pour une bibliotheque finie", humanDays(days)))
	case days <= 730:
		h.Level = LevelDormant
		h.Notes = append(h.Notes, fmt.Sprintf("aucun envoi depuis %s", humanDays(days)))
	default:
		h.Level = LevelAbandoned
		h.Notes = append(h.Notes, fmt.Sprintf("aucun envoi depuis %s, considerer le projet comme arrete", humanDays(days)))
	}

	// A high open-issue ratio on a popular project usually means maintenance
	// stopped keeping up with use, which is a dependency risk even when the
	// code still works.
	if r.Stars >= 100 && h.IssueRatio > 20 {
		h.Notes = append(h.Notes, fmt.Sprintf("%.0f issues ouvertes pour cent etoiles, la maintenance ne suit pas l'usage", h.IssueRatio))
		if h.Level == LevelHealthy {
			h.Level = LevelCalm
		}
	}

	if r.Fork {
		h.Notes = append(h.Notes, "ce depot est un fork, verifier s'il diverge reellement de l'original")
	}
	if r.License == "" || r.License == "NOASSERTION" {
		h.Notes = append(h.Notes, "licence absente ou non identifiee, l'usage n'est pas juridiquement clair")
	}

	return h
}

// Sort modes. Relevance is the default; the others exist because "the best
// result" is not the same question for everyone.
const (
	// SortRelevance balances term precision, language, health and a modest
	// popularity tiebreaker.
	SortRelevance = "pertinence"
	// SortPopular puts the widely adopted first. Useful when the cost of
	// picking wrong is high and a large user base is itself the reassurance.
	SortPopular = "populaire"
	// SortNiche surfaces small, precise projects that popularity ordering
	// buries. A tool that only ever shows the famous answer is a tool that
	// cannot find the specific one.
	SortNiche = "niche"
	// SortRecent orders by last push, for finding what is moving now.
	SortRecent = "recent"
	// SortHealth orders by how safely a repository can be depended upon.
	SortHealth = "sante"
)

// Score reorders results against the intent, in the requested mode.
//
// The default weights favour precision over popularity. A term in the
// repository name is worth far more than the same term buried in a
// description, because someone naming their project after a concept usually
// built that concept.
func Score(repos []model.Repo, in model.Intent, mode string) []model.Repo {
	terms := lowered(in.Terms)

	out := make([]model.Repo, len(repos))
	copy(out, repos)

	for i := range out {
		r := &out[i]
		r.Health = Rate(*r)
		r.Script = DetectScript(r.Description)
		r.Score = 0
		r.Why = nil

		name := strings.ToLower(r.Name)
		full := strings.ToLower(r.FullName)
		desc := strings.ToLower(r.Description)
		topics := lowered(r.Topics)

		matchedName, matchedDesc, matchedTopic := 0, 0, 0
		for _, t := range terms {
			switch {
			case name == t:
				r.Score += 12
				matchedName++
			case strings.Contains(name, t):
				r.Score += 6
				matchedName++
			case strings.Contains(full, t):
				r.Score += 3
				matchedName++
			}
			if strings.Contains(desc, t) {
				r.Score += 2
				matchedDesc++
			}
			for _, topic := range topics {
				if topic == t {
					r.Score += 4
					matchedTopic++
					break
				}
			}
		}

		if matchedName > 0 {
			r.Why = append(r.Why, fmt.Sprintf("%d terme(s) dans le nom", matchedName))
		}
		if matchedTopic > 0 {
			r.Why = append(r.Why, fmt.Sprintf("%d terme(s) dans les sujets", matchedTopic))
		}
		if matchedDesc > 0 {
			r.Why = append(r.Why, fmt.Sprintf("%d terme(s) dans la description", matchedDesc))
		}

		// Covering every term matters more than matching one of them many
		// times: a result that answers the whole question beats one that
		// answers a fragment loudly.
		if len(terms) > 1 && matchedName+matchedTopic >= len(terms) {
			r.Score += 8
			r.Why = append(r.Why, "couvre tous les termes demandes")
		}

		if in.Language != "" && strings.EqualFold(r.Language, in.Language) {
			r.Score += 5
			r.Why = append(r.Why, "langage demande")
		}

		// Popularity is a tiebreaker, not a driver. Logarithmic so that a
		// project with fifty thousand stars does not simply erase the field.
		switch mode {
		case SortPopular:
			if r.Stars > 0 {
				r.Score += math.Log10(float64(r.Stars)) * 10
			}
		case SortNiche:
			// Inverted, and only above a floor: a project with three stars is
			// not "niche", it is unproven. The bonus targets the band where a
			// small project is plausibly a deliberate, focused answer.
			if r.Stars >= 20 && r.Stars <= 2000 {
				r.Score += 8
				r.Why = append(r.Why, "projet cible plutot que generaliste")
			} else if r.Stars > 2000 {
				r.Score -= math.Log10(float64(r.Stars)) * 3
			}
		default:
			if r.Stars > 0 {
				r.Score += math.Log10(float64(r.Stars)) * 2
			}
		}

		// Agreement between independent ways of asking is worth more than any
		// single-list weighting: a project found by the name search and the
		// topic search and the exact-phrase search is the answer, and no
		// scoring formula applied to one list could have said so.
		if r.Agreement > 0 {
			r.Score += r.Agreement * 2
			if len(r.FoundBy) > 1 {
				r.Why = append(r.Why, "trouve par "+strconv.Itoa(len(r.FoundBy))+" recherches differentes")
			} else if len(r.FoundBy) == 1 {
				r.Why = append(r.Why, "trouve par: "+r.FoundBy[0])
			}
		}

		r.Score += healthBonus(r.Health)
		if r.Health.Level == LevelHealthy {
			r.Why = append(r.Why, "maintenu recemment")
		}
		if r.Health.Level == LevelAbandoned || r.Health.Level == LevelArchived {
			r.Why = append(r.Why, "penalise: projet arrete")
		}
	}

	switch mode {
	case SortRecent:
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].PushedAt.After(out[j].PushedAt)
		})
	case SortHealth:
		sort.SliceStable(out, func(i, j int) bool {
			li, lj := healthOrder(out[i].Health.Level), healthOrder(out[j].Health.Level)
			if li != lj {
				return li < lj
			}
			return out[i].Score > out[j].Score
		})
	default:
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Score != out[j].Score {
				return out[i].Score > out[j].Score
			}
			return out[i].Stars > out[j].Stars
		})
	}
	return out
}

func healthOrder(level string) int {
	switch level {
	case LevelHealthy:
		return 0
	case LevelCalm:
		return 1
	case LevelDormant:
		return 2
	case LevelAbandoned:
		return 3
	case LevelArchived:
		return 4
	default:
		return 5
	}
}

// healthBonus turns a health level into a score adjustment.
//
// The abandoned penalty is large by design. A dependency nobody maintains is
// not a slightly worse option, it is a different kind of decision, and burying
// it below the alternatives is the honest presentation.
func healthBonus(h model.Health) float64 {
	switch h.Level {
	case LevelHealthy:
		return 6
	case LevelCalm:
		return 2
	case LevelDormant:
		return -4
	case LevelAbandoned:
		return -10
	case LevelArchived:
		return -14
	default:
		return 0
	}
}

func humanDays(days int) string {
	switch {
	case days < 0:
		return "une duree inconnue"
	case days == 0:
		return "moins d'un jour"
	case days == 1:
		return "un jour"
	case days < 60:
		return fmt.Sprintf("%d jours", days)
	case days < 730:
		return fmt.Sprintf("%d mois", days/30)
	default:
		return fmt.Sprintf("%d ans", days/365)
	}
}

func lowered(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
