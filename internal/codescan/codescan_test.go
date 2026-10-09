// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"errors"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

// fakeScanner est un double injecte: il ne touche ni binaire ni reseau.
type fakeScanner struct {
	name      string
	available bool
	findings  []finding.Finding
	err       error
}

func (f fakeScanner) Name() string    { return f.name }
func (f fakeScanner) Available() bool { return f.available }
func (f fakeScanner) Scan(context.Context, string) ([]finding.Finding, error) {
	return f.findings, f.err
}

func TestRunAggregatesAndFlagsUnavailable(t *testing.T) {
	dir := t.TempDir()

	ok := fakeScanner{
		name:      "ok",
		available: true,
		findings: []finding.Finding{
			{ID: "A", Title: "x", Severity: finding.SeverityHigh, Status: finding.StatusReview},
		},
	}
	absent := fakeScanner{name: "absent", available: false}
	broken := fakeScanner{name: "broken", available: true, err: errors.New("boom")}

	rep, err := Run(context.Background(), dir, "test", ok, absent, broken)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Tool.Name != "quaero" {
		t.Errorf("outil = %q, attendu quaero", rep.Tool.Name)
	}
	if got := len(rep.Findings); got != 3 {
		t.Fatalf("constats = %d, attendu 3 (1 reel + 1 absent + 1 erreur)", got)
	}
	// Un analyseur absent laisse une trace plutot que de disparaitre.
	if !hasID(rep.Findings, "QRO-SCAN-ABSENT-absent") {
		t.Error("constat d'absence manquant pour l'analyseur non installe")
	}
	if !hasID(rep.Findings, "QRO-SCAN-ERREUR-broken") {
		t.Error("constat d'erreur manquant pour l'analyseur en echec")
	}
	// Tout constat de code reste non declare.
	for _, f := range rep.Findings {
		if f.Declared == nil || *f.Declared {
			t.Errorf("%s: Declared devrait etre false", f.ID)
		}
	}
}

func TestRunRejectsBadPath(t *testing.T) {
	if _, err := Run(context.Background(), "/chemin/inexistant/xyz", "test"); err == nil {
		t.Fatal("un chemin inexistant devrait echouer")
	}
}

func TestParseGovulncheckReachable(t *testing.T) {
	raw := []byte(`
{"osv":{"id":"GO-2023-1234","summary":"Panique dans example.com/foo","details":"detail","aliases":["CVE-2023-9999","GHSA-aaaa-bbbb-cccc"],"references":[{"type":"REPORT","url":"https://pkg.go.dev/vuln/GO-2023-1234"}]}}
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/foo","version":"v1.2.0","package":"example.com/foo"}]}}
{"finding":{"osv":"GO-2023-1234","fixed_version":"v1.2.3","trace":[{"module":"example.com/foo","version":"v1.2.0","package":"example.com/foo","function":"Vuln","position":{"filename":"main.go","line":42,"column":5}}]}}
`)
	fs, err := parseGovulncheck(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1 (dedoublonnage par OSV)", len(fs))
	}
	f := fs[0]
	if f.ID != "QRO-VULN-GO-2023-1234" {
		t.Errorf("ID = %q", f.ID)
	}
	// La frame atteignable (fonction + position) doit l'emporter: severite high.
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severite = %q, attendu high (symbole atteignable)", f.Severity)
	}
	if f.Status != finding.StatusReview {
		t.Errorf("status = %q, attendu review", f.Status)
	}
	if !hasRef(f.References, "OSV", "GO-2023-1234") {
		t.Error("reference OSV manquante")
	}
	if !hasRef(f.References, "CVE", "CVE-2023-9999") {
		t.Error("alias CVE non remonte en reference")
	}
	if !hasRef(f.References, "GHSA", "GHSA-aaaa-bbbb-cccc") {
		t.Error("alias GHSA non remonte en reference")
	}
	if f.Remediation == "" {
		t.Error("remediation vide alors qu'une version corrigee existe")
	}
}

func TestParseGovulncheckImportOnly(t *testing.T) {
	// Pas de fonction dans la trace: dependance vulnerable importee mais non
	// appelee. Severite medium, pas high.
	raw := []byte(`
{"osv":{"id":"GO-2024-0001","summary":"x","aliases":[]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/bar","version":"v0.1.0","package":"example.com/bar"}]}}
`)
	fs, err := parseGovulncheck(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(fs))
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Errorf("severite = %q, attendu medium (importe non appele)", fs[0].Severity)
	}
}

func TestParseGovulncheckEmpty(t *testing.T) {
	fs, err := parseGovulncheck([]byte(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("constats = %d, attendu 0", len(fs))
	}
}

func TestParseGosec(t *testing.T) {
	raw := []byte(`{"Issues":[
{"severity":"HIGH","confidence":"HIGH","rule_id":"G401","details":"Use of weak cryptographic primitive","file":"crypto.go","line":"10","column":"2","code":"h := md5.New()","cwe":{"id":"327","url":"https://cwe.mitre.org/data/definitions/327.html"}}
],"Stats":{"files":1}}`)
	fs, err := parseGosec(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(fs))
	}
	f := fs[0]
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severite = %q, attendu high", f.Severity)
	}
	if f.Status != finding.StatusReview {
		t.Errorf("status = %q, attendu review", f.Status)
	}
	if f.Target == nil || f.Target.Identifier != "crypto.go:10" {
		t.Errorf("cible = %+v, attendu crypto.go:10", f.Target)
	}
	if !hasRef(f.References, "CWE", "CWE-327") {
		t.Error("reference CWE-327 manquante")
	}
	if f.Declared == nil || *f.Declared {
		t.Error("Declared devrait etre false")
	}
}

func TestParseGosecEmpty(t *testing.T) {
	fs, err := parseGosec([]byte(`{"Issues":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("constats = %d, attendu 0", len(fs))
	}
}

func hasID(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func hasRef(refs []finding.Reference, framework, id string) bool {
	for _, r := range refs {
		if r.Framework == framework && r.ID == id {
			return true
		}
	}
	return false
}
