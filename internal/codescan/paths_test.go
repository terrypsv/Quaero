// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelTo(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quaero-scan-123")
	cases := []struct{ p, want string }{
		{filepath.Join(root, "internal", "github", "github.go"), "internal/github/github.go"},
		{filepath.Join(root, "main.go") + ":83", "main.go:83"},
		{"internal/a.go", "internal/a.go"},
		{"", ""},
	}
	for _, c := range cases {
		if got := relTo(root, c.p); got != c.want {
			t.Errorf("relTo(%q) = %q, attendu %q", c.p, got, c.want)
		}
	}
	// Sans racine, le chemin passe tel quel.
	abs := filepath.Join(root, "a.go")
	if got := relTo("", abs); got != abs {
		t.Errorf("sans racine: %q", got)
	}
	// Hors de la racine, le chemin reste absolu: on ne pretend pas qu'il est
	// dans le depot.
	out := filepath.Join(t.TempDir(), "ailleurs", "b.go")
	if got := relTo(root, out); got != out {
		t.Errorf("hors racine: %q", got)
	}
}

// La racine peut etre ecrite autrement par le moteur (nom court Windows,
// /private/var sous macOS): le nom du dossier temporaire suffit a couper.
func TestRelToRacineEcriteAutrement(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"var", "folders", "quaero-scan-777")
	p := filepath.Join(string(filepath.Separator)+"private", "var", "folders", "quaero-scan-777", "internal", "a.go")
	if got := relTo(root, p); got != "internal/a.go" {
		t.Errorf("relTo = %q, attendu internal/a.go", got)
	}
}

// Deux scans du meme code dans deux clones differents donnent les memes
// identifiants: le dossier temporaire n'y apparait plus.
func TestIdentifiantStableEntreClones(t *testing.T) {
	ids := map[string]bool{}
	for _, base := range []string{"quaero-scan-111", "quaero-scan-222"} {
		root := filepath.Join(t.TempDir(), base)
		gosec, _ := json.Marshal(map[string]any{"Issues": []map[string]any{{
			"rule_id": "G101", "details": "Potential hardcoded credentials", "severity": "HIGH",
			"confidence": "LOW", "file": filepath.Join(root, "internal", "github", "github.go"), "line": "83",
		}}})
		fs, err := parseGosecAt(gosec, root)
		if err != nil || len(fs) != 1 {
			t.Fatalf("gosec: %v, %d constat(s)", err, len(fs))
		}
		ids[fs[0].ID] = true
		if strings.Contains(fs[0].ID, base) || fs[0].Target.Identifier != "internal/github/github.go:83" {
			t.Errorf("identifiant %q, cible %q", fs[0].ID, fs[0].Target.Identifier)
		}

		semgrep, _ := json.Marshal(map[string]any{"results": []map[string]any{{
			"check_id": "python.lang.security.audit.x.x", "path": filepath.Join(root, "scripts", "a.py"),
			"start": map[string]int{"line": 54}, "extra": map[string]any{"message": "m", "severity": "WARNING"},
		}}})
		ss, err := parseSemgrepAt(semgrep, root)
		if err != nil || len(ss) != 1 {
			t.Fatalf("semgrep: %v, %d constat(s)", err, len(ss))
		}
		ids[ss[0].ID] = true
		if ss[0].Target.Identifier != "scripts/a.py:54" {
			t.Errorf("cible semgrep %q", ss[0].Target.Identifier)
		}
	}
	if len(ids) != 2 {
		t.Errorf("%d identifiants differents pour 2 constats sur 2 clones, attendu 2: %v", len(ids), ids)
	}
}

// Un identifiant ne garde aucune barre oblique inverse, quel que soit le
// systeme qui a produit le chemin.
func TestSanitizeBarreInverse(t *testing.T) {
	if got := sanitize(`internal\github\github.go:83`); strings.ContainsAny(got, `\/:.`) {
		t.Errorf("sanitize = %q", got)
	}
}
