// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package advisory

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

func report() *finding.Report {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{
		"cible":  "github.com/exemple/projet",
		"commit": "0123456789abcdef0123456789abcdef01234567",
	})
	rep.Add(finding.Finding{
		ID: "QRO-SCAN-ABSENT-gosec", Title: "Analyseur non disponible: gosec",
		Severity: finding.SeverityInfo, Status: finding.StatusReview,
	})
	rep.Add(finding.Finding{
		ID:          "QRO-SEMGREP-tainted-sql-string-app-db-py-42",
		Title:       "tainted-sql-string: user input reaches a SQL query",
		Description: "User input flows into a SQL string built by concatenation.",
		Severity:    finding.SeverityHigh, Status: finding.StatusReview,
		Target: &finding.Target{Type: "code", Identifier: "app/db.py:42"},
		Evidence: []finding.Evidence{
			{Type: "code", Data: `cur.execute("SELECT * FROM t WHERE id=" + uid)`},
			{Type: "rule", Data: "python.lang.security.audit.tainted-sql-string"},
			{Type: "engine", Data: "semgrep"},
		},
		References: []finding.Reference{{Framework: "CWE", ID: "CWE-89"}},
	})
	rep.Add(finding.Finding{
		ID: "QRO-OSV-GHSA-xxxx-yyyy-zzzz-requests", Title: "requests: credentials leak on redirect",
		Severity: finding.SeverityMedium, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "dependency", Identifier: "requests@2.20.0"},
		Evidence: []finding.Evidence{{Type: "url", Data: "https://example.org/advisory"}},
		References: []finding.Reference{
			{Framework: "OSV", ID: "GHSA-xxxx-yyyy-zzzz"},
			{Framework: "CVE", ID: "CVE-2099-0001"},
		},
	})
	rep.Finish()
	return rep
}

// Les constats sur le scan lui-meme ne deviennent jamais un signalement.
func TestCandidatsSansConstatsDeScan(t *testing.T) {
	cands := Candidates(report())
	if len(cands) != 2 {
		t.Fatalf("%d candidats, attendu 2", len(cands))
	}
	for _, f := range cands {
		if strings.HasPrefix(f.ID, "QRO-SCAN-") {
			t.Errorf("constat de scan propose: %s", f.ID)
		}
	}
	if _, err := Find(report(), "QRO-SCAN-ABSENT-gosec"); err == nil {
		t.Error("un constat de scan doit etre refuse")
	}
	if _, err := Find(report(), "QRO-INCONNU"); err == nil {
		t.Error("un identifiant inconnu doit etre refuse")
	}
}

// Le brouillon porte ce que le scan sait, et laisse a l'operateur ce que seul
// lui peut etablir.
func TestBrouillonCode(t *testing.T) {
	rep := report()
	f, err := Find(rep, "QRO-SEMGREP-tainted-sql-string-app-db-py-42")
	if err != nil {
		t.Fatal(err)
	}
	d := Draft(rep, f)
	for _, want := range []string{
		"BROUILLON NON VERIFIE",
		"instance locale montee soi-meme",
		"Ne rien publier",
		"**Repository:** github.com/exemple/projet",
		"`0123456789abcdef0123456789abcdef01234567`",
		"**Location:** `app/db.py:42`",
		"CWE-89",
		"https://cwe.mitre.org/data/definitions/89.html",
		"python.lang.security.audit.tainted-sql-string",
		"Reported by: semgrep",
		"## Reproduction",
		"## Impact",
		"TO COMPLETE",
		"**Proposed severity:** High",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("brouillon sans %q", want)
		}
	}
	// La liste de controle de l'operateur est un commentaire, qui ne
	// s'affiche pas si le brouillon est colle tel quel.
	if !strings.HasPrefix(d, "<!--") {
		t.Error("la liste de controle doit ouvrir le brouillon en commentaire")
	}
}

// Une vulnerabilite de dependance deja publique: le brouillon rappelle de
// verifier que le projet est touche avant tout signalement prive.
func TestBrouillonDependancePublique(t *testing.T) {
	rep := report()
	f, err := Find(rep, "QRO-OSV-GHSA-xxxx-yyyy-zzzz-requests")
	if err != nil {
		t.Fatal(err)
	}
	d := Draft(rep, f)
	for _, want := range []string{
		"**Dependency:** `requests@2.20.0`",
		"deja publique",
		"reellement touche",
		"https://www.cve.org/CVERecord?id=CVE-2099-0001",
		"https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
		"https://example.org/advisory",
		"Upgrade the dependency",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("brouillon sans %q", want)
		}
	}
}

// Sans cible ni commit dans le rapport, le brouillon ne les invente pas.
func TestBrouillonSansContexte(t *testing.T) {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", nil)
	f := finding.Finding{ID: "QRO-GOSEC-G104-a-go-1", Title: "G104", Severity: finding.SeverityLow, Status: finding.StatusReview}
	rep.Add(f)
	d := Draft(rep, f)
	if strings.Contains(d, "**Repository:**") || strings.Contains(d, "Analyzed revision") {
		t.Errorf("contexte invente:\n%s", d)
	}
}

// Un dossier local analyse ne donne pas son chemin au brouillon: il decrit la
// machine de l'operateur, pas le depot du mainteneur.
func TestBrouillonDossierLocal(t *testing.T) {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{"cible": `C:\Users\moi\projet-prive`})
	f := finding.Finding{ID: "QRO-GOSEC-G104-a-go-1", Title: "G104", Severity: finding.SeverityLow, Status: finding.StatusReview,
		Evidence: []finding.Evidence{{Type: "fusionne", Data: "autre titre (semgrep)"}}}
	rep.Add(f)
	d := Draft(rep, f)
	if strings.Contains(d, "projet-prive") || !strings.Contains(d, "TO COMPLETE (scanned from a local copy)") {
		t.Errorf("chemin local dans le brouillon:\n%s", d)
	}
	if !strings.Contains(d, "Also reported on the same line as: autre titre (semgrep).") {
		t.Errorf("fusion absente du brouillon:\n%s", d)
	}
}

// Le brouillon propose la version qui corrige et la commande, ou la correction
// que la regle donne pour la ligne signalee.
func TestBrouillonCorrection(t *testing.T) {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", nil)
	dep := finding.Finding{ID: "QRO-VULN-GO-1", Title: "x/net", Severity: finding.SeverityHigh, Status: finding.StatusReview,
		Target: &finding.Target{Type: "dependency", Identifier: "golang.org/x/net@0.35.0"},
		Evidence: []finding.Evidence{{Type: "version_cible", Data: "0.38.0"},
			{Type: "commande", Data: "go get golang.org/x/net@v0.38.0"}, {Type: "commande", Data: "go mod tidy"}}}
	code := finding.Finding{ID: "QRO-SEMGREP-x", Title: "md5", Severity: finding.SeverityLow, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "code", Identifier: "a.go:2"},
		Evidence: []finding.Evidence{{Type: "correctif", Data: "sha256.New()"}}}
	rep.Add(dep)
	rep.Add(code)
	if d := Draft(rep, dep); !strings.Contains(d, "Upgrade the dependency to `0.38.0` or later") ||
		!strings.Contains(d, "```\ngo get golang.org/x/net@v0.38.0\ngo mod tidy\n```") {
		t.Errorf("dependance:\n%s", d)
	}
	if d := Draft(rep, code); !strings.Contains(d, "The rule proposes this replacement for the reported line:\n\n```\nsha256.New()\n```") {
		t.Errorf("code:\n%s", d)
	}
}

// Une version venue d'un rapport importe ne ferme pas le code en ligne pour
// glisser un lien dans le brouillon.
func TestBrouillonVersionEchappee(t *testing.T) {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", nil)
	dep := finding.Finding{ID: "QRO-OSV-x", Title: "x", Severity: finding.SeverityLow, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "dependency", Identifier: "x@1.0.0"},
		Evidence: []finding.Evidence{{Type: "version_cible", Data: "1.0` [x](https://evil) `"}}}
	rep.Add(dep)
	if d := Draft(rep, dep); !strings.Contains(d, "to `1.0' [x](https://evil) '` or later") {
		t.Errorf("version non echappee:\n%s", d)
	}
}
