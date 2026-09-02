// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package audit evalue la sante des depots correspondant a une requete et
// projette chaque verdict en constat au schema de constat partage, consommable
// par Acta. Il ne juge pas differemment de l'interface web: il reutilise la
// meme lecture d'intention, la meme recherche et la meme notation de sante, et
// traduit le Health obtenu en fail, review ou pass.
package audit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/intent"
	"github.com/terrypsv/Quaero/internal/model"
	"github.com/terrypsv/Quaero/internal/rank"
)

// Searcher est la capacite de recherche dont l'audit a besoin. *github.Client la
// satisfait; les tests injectent un double, sans reseau.
type Searcher interface {
	Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error)
}

// Run lit une requete, recupere les depots, evalue leur sante et emet le rapport.
func Run(ctx context.Context, s Searcher, phrase string, limit int, version string) (*finding.Report, error) {
	in := intent.Read(phrase)
	query := intent.Query(in)

	repos, total, _, err := s.Search(ctx, query, limit, 1)
	if err != nil {
		return nil, fmt.Errorf("recherche: %w", err)
	}

	host, _ := os.Hostname()
	rep := finding.NewReport(
		finding.Tool{Name: "quaero", Version: version},
		host,
		map[string]any{
			"query":         phrase,
			"github_query":  query,
			"evaluated":     len(repos),
			"total_matches": total,
		},
	)

	for _, r := range repos {
		rep.Add(project(r, rank.Rate(r)))
	}

	rep.Finish()
	return rep, nil
}

func project(r model.Repo, h model.Health) finding.Finding {
	severity, status := classify(r, h)

	f := finding.Finding{
		ID:          "QRO-" + token(r.FullName),
		Title:       healthTitle(h.Level) + ": " + r.FullName,
		Category:    "supply-chain",
		Severity:    severity,
		Status:      status,
		Target:      &finding.Target{Type: "repository", Identifier: r.FullName},
		Observed:    observed(r, h),
		Remediation: remediationFor(h.Level),
	}
	if r.URL != "" {
		f.Evidence = append(f.Evidence, finding.Evidence{Type: "url", Data: r.URL})
	}
	for _, n := range h.Notes {
		f.Evidence = append(f.Evidence, finding.Evidence{Type: "health", Data: n})
	}
	return f
}

// classify traduit un niveau de sante en gravite et statut. L'activite prime;
// une licence absente sur un depot par ailleurs sain reste un risque d'adoption,
// pas un echec franc.
func classify(r model.Repo, h model.Health) (finding.Severity, finding.Status) {
	switch h.Level {
	case rank.LevelAbandoned, rank.LevelArchived:
		return finding.SeverityHigh, finding.StatusFail
	case rank.LevelDormant:
		return finding.SeverityMedium, finding.StatusReview
	}
	if r.License == "" || r.License == "NOASSERTION" {
		return finding.SeverityLow, finding.StatusReview
	}
	return finding.SeverityInfo, finding.StatusPass
}

func healthTitle(level string) string {
	switch level {
	case rank.LevelHealthy:
		return "Depot sain"
	case rank.LevelCalm:
		return "Depot calme"
	case rank.LevelDormant:
		return "Depot dormant"
	case rank.LevelAbandoned:
		return "Depot abandonne"
	case rank.LevelArchived:
		return "Depot archive"
	default:
		return "Depot"
	}
}

func remediationFor(level string) string {
	switch level {
	case rank.LevelAbandoned, rank.LevelArchived:
		return "Ne pas adopter comme dependance active: chercher un fork maintenu ou une alternative."
	case rank.LevelDormant:
		return "Verifier si le projet est termine ou delaisse avant d'en dependre."
	default:
		return "Verifier la licence avant d'en dependre."
	}
}

func observed(r model.Repo, h model.Health) string {
	if h.DaysSincePush < 0 {
		return fmt.Sprintf("sante %s, derniere activite inconnue", h.Level)
	}
	return fmt.Sprintf("sante %s, dernier envoi il y a %d jour(s)", h.Level, h.DaysSincePush)
}

func token(full string) string {
	return strings.NewReplacer("/", "-", ".", "-", ":", "-", " ", "-").Replace(full)
}
