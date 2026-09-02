// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/audit"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/model"
)

type stubSearcher struct {
	repos []model.Repo
}

func (s stubSearcher) Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error) {
	return s.repos, len(s.repos), github.RateLimit{}, nil
}

func find(fs []finding.Finding, id string) (finding.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func TestProjectionSanteVersConstat(t *testing.T) {
	now := time.Now()
	repos := []model.Repo{
		{FullName: "acme/vivant", Owner: "acme", Name: "vivant", License: "MIT", URL: "https://x/1", PushedAt: now.AddDate(0, 0, -10)},
		{FullName: "acme/mort", Owner: "acme", Name: "mort", License: "MIT", PushedAt: now.AddDate(-3, 0, 0)},
		{FullName: "acme/archive", Owner: "acme", Name: "archive", License: "MIT", Archived: true},
		{FullName: "acme/sanslicence", Owner: "acme", Name: "sanslicence", License: "", PushedAt: now.AddDate(0, 0, -5)},
	}

	rep, err := audit.Run(context.Background(), stubSearcher{repos}, "peu importe", 30, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 4 {
		t.Fatalf("4 constats attendus, obtenu %d", len(rep.Findings))
	}

	if f, ok := find(rep.Findings, "QRO-acme-vivant"); !ok || f.Status != finding.StatusPass {
		t.Fatalf("depot sain attendu en pass, obtenu %+v", f)
	}
	if f, ok := find(rep.Findings, "QRO-acme-mort"); !ok || f.Status != finding.StatusFail || f.Severity != finding.SeverityHigh {
		t.Fatalf("depot abandonne attendu en fail/high, obtenu %+v", f)
	}
	if f, ok := find(rep.Findings, "QRO-acme-archive"); !ok || f.Status != finding.StatusFail {
		t.Fatalf("depot archive attendu en fail, obtenu %+v", f)
	}
	if f, ok := find(rep.Findings, "QRO-acme-sanslicence"); !ok || f.Status != finding.StatusReview {
		t.Fatalf("depot sans licence attendu en review, obtenu %+v", f)
	}
}

func TestEvidencePorteLesNotes(t *testing.T) {
	repos := []model.Repo{
		{FullName: "acme/archive", Owner: "acme", Name: "archive", Archived: true, URL: "https://x/2"},
	}
	rep, err := audit.Run(context.Background(), stubSearcher{repos}, "x", 30, "test")
	if err != nil {
		t.Fatal(err)
	}
	f, ok := find(rep.Findings, "QRO-acme-archive")
	if !ok {
		t.Fatalf("constat attendu, obtenu %+v", rep.Findings)
	}
	// l'URL et au moins une note de sante doivent figurer en evidence
	var hasURL, hasHealth bool
	for _, e := range f.Evidence {
		if e.Type == "url" {
			hasURL = true
		}
		if e.Type == "health" {
			hasHealth = true
		}
	}
	if !hasURL || !hasHealth {
		t.Fatalf("evidence incomplete: url=%v health=%v (%+v)", hasURL, hasHealth, f.Evidence)
	}
}
