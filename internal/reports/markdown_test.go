// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/triage"
)

func exportSample() *finding.Report {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "1.2.3"}, "h", map[string]any{
		"cible": "github.com/acme/outil", "commit": "1e21e54a1375d5badd8c62fcd77d4dbc505a209d",
		"scanners": []any{"semgrep", "osv-scanner"}, "durees_s": map[string]any{"semgrep": 14.5, "osv-scanner": 4.0},
		"go_compile": "go1.27.2",
	})
	code := func(id, title, loc string, sev finding.Severity, ev ...finding.Evidence) finding.Finding {
		return finding.Finding{ID: id, Title: title, Severity: sev, Status: finding.StatusReview,
			Target: &finding.Target{Type: "code", Identifier: loc}, Evidence: ev}
	}
	dep := func(id, module string, tags ...string) finding.Finding {
		f := finding.Finding{ID: id, Title: "faille " + id, Severity: finding.SeverityMedium, Status: finding.StatusReview,
			Target: &finding.Target{Type: "dependency", Identifier: module}, References: []finding.Reference{{Framework: "OSV", ID: id}}}
		for _, t := range tags {
			f.Evidence = append(f.Evidence, finding.Evidence{Type: "contexte", Data: t})
		}
		return f
	}
	rep.Add(code("A1", "exec: commande variable.", "cmd/a.go:3", finding.SeverityHigh,
		finding.Evidence{Type: "engine", Data: "semgrep"}, finding.Evidence{Type: "code", Data: "x := \"```\"\nexec.Command(x)"}))
	rep.Add(code("A2", "exec: commande variable.", "cmd/b.go:9", finding.SeverityHigh))
	rep.Add(code("B", "<script>alert(1)</script>\n# titre glisse [lien](javascript:x)", "web/x.js:1", finding.SeverityMedium))
	rep.Add(code("T", "secret en dur", "a_test.go:4", finding.SeverityHigh, finding.Evidence{Type: "contexte", Data: "test"}))
	rep.Add(code("F", "faux", "c.go:1", finding.SeverityLow))
	rep.Add(dep("GO-1", "golang.org/x/net@0.35.0", "inutilise"))
	rep.Add(dep("GO-2", "golang.org/x/net@0.35.0", "inutilise"))
	rep.Add(dep("GO-3", "golang.org/x/crypto@0.33.0", "inutilise"))
	rep.Add(dep("GO-4", "golang.org/x/crypto@0.33.0"))
	rep.Add(dep("GO-5", "stdlib@1.25"))
	rep.Add(finding.Finding{ID: "QRO-SCAN-ABSENT-gosec", Title: "absent", Severity: finding.SeverityInfo, Status: finding.StatusReview})
	rep.Finish()
	return rep
}

// L'export range comme la page, regroupe par regle, dit le tri, et ne laisse
// aucun champ du rapport ouvrir une balise, un titre ou fermer un bloc.
func TestExportMarkdown(t *testing.T) {
	rep := exportSample()
	md := Markdown(rep, map[string]triage.Decision{
		"A2": {State: triage.Confirmed, Note: "appel\nreel"},
		"F":  {State: triage.FalsePositive},
	}, time.Date(2026, 10, 18, 18, 30, 0, 0, time.Local))

	order := []string{"# Rapport Quaero, acme/outil", "## Résumé", "## À vérifier (3)", "## Dépendances (2)",
		"## Tests et exemples (1)", "## Dépendances inutilisées (1)", "## Faux positifs (1)", "Exporté par Quaero 1.2.3 le 18/10/2026 à 18h30."}
	at := 0
	for _, want := range order {
		i := strings.Index(md[at:], want)
		if i < 0 {
			t.Fatalf("%q absent ou mal place:\n%s", want, md)
		}
		at += i + len(want)
	}
	for _, want := range []string{
		"### [ÉLEVÉE] exec: commande variable, 2 endroits",
		"- `cmd/b.go:9`. Confirmé, appel reel",
		"  ````\n  x := \"```\"\n  exec.Command(x)\n  ````",
		`\<script>alert(1)\</script> # titre glisse \[lien](javascript:x)`,
		"golang.org/x/net 0.35.0, 2 vulnérabilités publiées",
		"govulncheck a compilé avec go1.27.2.",
		"gosec (absent)",
		"semgrep 14,5 s, osv-scanner 4 s",
		"commit 1e21e54,",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("%q absent:\n%s", want, md)
		}
	}
	// x/crypto a une faille sur un module importe: il reste dans les
	// dependances, en entier.
	unused := md[strings.Index(md, "## Dépendances inutilisées"):]
	if strings.Contains(unused, "crypto") || !strings.Contains(unused, "x/net") {
		t.Errorf("section inutilisees:\n%s", unused)
	}
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "# ") && !strings.HasPrefix(l, "# Rapport Quaero") {
			t.Errorf("titre ouvert par un champ: %q", l)
		}
	}
	if name := ExportName(rep); !strings.HasPrefix(name, "acme-outil_") || !strings.HasSuffix(name, ".md") {
		t.Errorf("nom %q", name)
	}
}
