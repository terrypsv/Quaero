// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

// vuln fabrique un constat de vulnerabilite connue tel qu'un moteur l'emet,
// avec sa preuve de provenance.
func vuln(id string, sev finding.Severity, engine string, refs ...finding.Reference) finding.Finding {
	return finding.Finding{
		ID:         id,
		Severity:   sev,
		Status:     finding.StatusReview,
		Category:   Category,
		References: refs,
		Evidence:   []finding.Evidence{{Type: EvidenceEngine, Data: engine}},
	}
}

func osvRef(id string) finding.Reference { return finding.Reference{Framework: "OSV", ID: id} }
func cveRef(id string) finding.Reference { return finding.Reference{Framework: "CVE", ID: id} }

func engines(f finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, e := range f.Evidence {
		if e.Type == EvidenceEngine {
			out[e.Data] = true
		}
	}
	return out
}

func TestDedupeGardeGovulncheckAtteignable(t *testing.T) {
	// Le cas observe sur Quaero: osv-scanner (medium) puis govulncheck (high)
	// sur la meme vulnerabilite de la bibliotheque standard.
	fs := []finding.Finding{
		vuln("QRO-OSV-GO-2026-6603-stdlib", finding.SeverityMedium, "osv-scanner", osvRef("GO-2026-6603")),
		vuln("QRO-VULN-GO-2026-6603", finding.SeverityHigh, "govulncheck", osvRef("GO-2026-6603")),
	}
	got := dedupe(fs)
	if len(got) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(got))
	}
	if got[0].ID != "QRO-VULN-GO-2026-6603" || got[0].Severity != finding.SeverityHigh {
		t.Errorf("survivant = %s (%s), attendu le constat govulncheck high", got[0].ID, got[0].Severity)
	}
	if e := engines(got[0]); !e["govulncheck"] || !e["osv-scanner"] {
		t.Errorf("provenance = %v, attendu les deux moteurs", e)
	}
}

func TestDedupeEgaliteGraviteDepartageParMoteur(t *testing.T) {
	// Meme gravite: govulncheck l'emporte, il sait que le code n'est pas appele.
	fs := []finding.Finding{
		vuln("QRO-OSV-GO-1-stdlib", finding.SeverityMedium, "osv-scanner", osvRef("GO-1")),
		vuln("QRO-VULN-GO-1", finding.SeverityMedium, "govulncheck", osvRef("GO-1")),
	}
	got := dedupe(fs)
	if len(got) != 1 || got[0].ID != "QRO-VULN-GO-1" {
		t.Fatalf("attendu un seul constat govulncheck, obtenu %+v", got)
	}
}

func TestDedupeParAliasCVE(t *testing.T) {
	// Identifiants OSV differents, meme CVE: c'est la meme faille.
	fs := []finding.Finding{
		vuln("A", finding.SeverityMedium, "osv-scanner", osvRef("GHSA-xxxx"), cveRef("CVE-2026-1")),
		vuln("B", finding.SeverityHigh, "govulncheck", osvRef("GO-2026-1"), cveRef("CVE-2026-1")),
	}
	if got := dedupe(fs); len(got) != 1 || got[0].ID != "B" {
		t.Fatalf("attendu une fusion par alias CVE vers B, obtenu %+v", got)
	}
}

func TestDedupeNeFusionneJamaisSansIdentifiantPublic(t *testing.T) {
	// Deux motifs gosec au meme CWE dans deux fichiers restent deux constats.
	cwe := finding.Reference{Framework: "CWE", ID: "CWE-78"}
	fs := []finding.Finding{
		vuln("QRO-GOSEC-G204-a", finding.SeverityMedium, "gosec", cwe),
		vuln("QRO-GOSEC-G204-b", finding.SeverityMedium, "gosec", cwe),
		vuln("QRO-SCAN-ABSENT-semgrep", finding.SeverityInfo, "semgrep"),
	}
	if got := dedupe(fs); len(got) != 3 {
		t.Fatalf("constats = %d, attendu 3 (aucune fusion)", len(got))
	}
}

func TestDedupeVulnerabilitesDistinctes(t *testing.T) {
	fs := []finding.Finding{
		vuln("A", finding.SeverityHigh, "govulncheck", osvRef("GO-1")),
		vuln("B", finding.SeverityHigh, "govulncheck", osvRef("GO-2")),
	}
	if got := dedupe(fs); len(got) != 2 {
		t.Fatalf("constats = %d, attendu 2", len(got))
	}
}

func TestRunFusionneEtLeDit(t *testing.T) {
	osv := fakeScanner{name: "osv-scanner", available: true, findings: []finding.Finding{
		{ID: "QRO-OSV-GO-9-stdlib", Severity: finding.SeverityMedium, References: []finding.Reference{osvRef("GO-9")}},
	}}
	gvc := fakeScanner{name: "govulncheck", available: true, findings: []finding.Finding{
		{ID: "QRO-VULN-GO-9", Severity: finding.SeverityHigh, References: []finding.Reference{osvRef("GO-9")}},
	}}
	rep, err := Run(context.Background(), t.TempDir(), "test", osv, gvc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "QRO-VULN-GO-9" {
		t.Fatalf("attendu un seul constat govulncheck, obtenu %+v", rep.Findings)
	}
	if n, _ := rep.Run.Context["doublons_fusionnes"].(int); n != 1 {
		t.Errorf("doublons_fusionnes = %v, attendu 1", rep.Run.Context["doublons_fusionnes"])
	}
	if e := engines(rep.Findings[0]); !e["govulncheck"] || !e["osv-scanner"] {
		t.Errorf("provenance = %v, attendu les deux moteurs", e)
	}
}

// Deux constats de meme identifiant (meme regle, meme ligne, ou deux chemins
// que l'assainissement confond) en gardent deux distincts, et le premier ne
// change pas.
func TestIdentifiantsUniques(t *testing.T) {
	fs := uniqueIDs([]finding.Finding{
		{ID: "QRO-SEMGREP-r-a-js-3"}, {ID: "QRO-SEMGREP-r-a-js-3"},
		{ID: "QRO-SEMGREP-r-a-js-3-2"}, {ID: "QRO-SEMGREP-r-a-js-3"}, {ID: "autre"},
	})
	want := []string{"QRO-SEMGREP-r-a-js-3", "QRO-SEMGREP-r-a-js-3-3", "QRO-SEMGREP-r-a-js-3-2", "QRO-SEMGREP-r-a-js-3-4", "autre"}
	seen := map[string]bool{}
	for i, f := range fs {
		if f.ID != want[i] {
			t.Errorf("constat %d: %q, attendu %q", i, f.ID, want[i])
		}
		if seen[f.ID] {
			t.Errorf("identifiant %q en double", f.ID)
		}
		seen[f.ID] = true
	}
}

func codeAt(id, loc, engine string, sev finding.Severity, cwe string) finding.Finding {
	f := finding.Finding{
		ID: id, Title: id + " titre", Severity: sev, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "code", Identifier: loc},
		Evidence: []finding.Evidence{{Type: EvidenceEngine, Data: engine}},
	}
	if cwe != "" {
		f.References = []finding.Reference{{Framework: "CWE", ID: cwe}}
	}
	return f
}

// semgrep et gosec sur la meme ligne ne font qu'un constat, le plus grave, qui
// garde les deux moteurs, les deux CWE et le titre de l'autre.
func TestMemeLigneDeuxMoteurs(t *testing.T) {
	fs := mergeSameLine([]finding.Finding{
		codeAt("QRO-SEMGREP-exec", "util.go:27", "semgrep", finding.SeverityHigh, "CWE-94"),
		codeAt("QRO-GOSEC-G204", "util.go:27", "gosec", finding.SeverityMedium, "CWE-78"),
		codeAt("QRO-GOSEC-G204-b", "util.go:28", "gosec", finding.SeverityMedium, "CWE-78"),
	})
	if len(fs) != 2 {
		t.Fatalf("%d constats, attendu 2: %+v", len(fs), fs)
	}
	m := fs[0]
	if m.ID != "QRO-SEMGREP-exec" || m.Severity != finding.SeverityHigh {
		t.Errorf("survivant %s %s", m.ID, m.Severity)
	}
	if e := enginesOf(m); !e["semgrep"] || !e["gosec"] {
		t.Errorf("moteurs %v", e)
	}
	if len(m.References) != 2 {
		t.Errorf("references %v", m.References)
	}
	merged := false
	for _, e := range m.Evidence {
		merged = merged || (e.Type == EvidenceMerged && strings.Contains(e.Data, "QRO-GOSEC-G204 titre (gosec)"))
	}
	if !merged {
		t.Errorf("titre de l'autre moteur perdu: %+v", m.Evidence)
	}
}

// La fusion ne depend pas de l'ordre, et ne perd ni description ni lien.
func TestMemeLigneOrdreEtContenu(t *testing.T) {
	a := codeAt("A", "x.go:3", "semgrep", finding.SeverityMedium, "")
	a.Description = "message semgrep complet"
	b := codeAt("B", "x.go:3", "gosec", finding.SeverityHigh, "")
	b.Evidence = append(b.Evidence, finding.Evidence{Type: "url", Data: "https://exemple/b"})
	c := codeAt("C", "x.go:3", "semgrep", finding.SeverityLow, "")
	d := codeAt("D", "x.go:3", "gosec", finding.SeverityLow, "")
	fs := mergeSameLine([]finding.Finding{a, b, c, d})
	if len(fs) != 2 {
		t.Fatalf("%d constats, attendu 2 (A+B, C+D)", len(fs))
	}
	if fs[0].ID != "B" || !strings.Contains(fs[0].Description, "message semgrep complet") {
		t.Errorf("survivant %s, description %q", fs[0].ID, fs[0].Description)
	}
	if e := enginesOf(fs[1]); !e["semgrep"] || !e["gosec"] {
		t.Errorf("C et D non fusionnes: %v", e)
	}
	a.Evidence = append(a.Evidence, finding.Evidence{Type: "url", Data: "https://exemple/a"})
	m := mergeSameLine([]finding.Finding{b, a})[0]
	n := 0
	for _, e := range m.Evidence {
		if e.Type == "url" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d liens gardes, attendu 2", n)
	}
}

// Deux regles du meme moteur, des dependances ou des constats sur le scan ne
// sont pas fusionnes par ligne.
func TestMemeLigneNonFusionnes(t *testing.T) {
	dep := codeAt("QRO-VULN-1", "mod@v1", "govulncheck", finding.SeverityHigh, "")
	dep.References = []finding.Reference{{Framework: "OSV", ID: "GO-1"}}
	fs := mergeSameLine([]finding.Finding{
		codeAt("A", "a.go:1", "semgrep", finding.SeverityHigh, ""),
		codeAt("B", "a.go:1", "semgrep", finding.SeverityLow, ""),
		dep,
		{ID: "QRO-SCAN-ABSENT-gosec", Target: &finding.Target{Type: "code", Identifier: "a.go:1"}},
	})
	if len(fs) != 4 {
		t.Errorf("%d constats, attendu 4", len(fs))
	}
}
