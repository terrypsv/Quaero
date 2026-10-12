// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

func writeReport(t *testing.T) string {
	t.Helper()
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{"cible": "github.com/a/b"})
	rep.Add(finding.Finding{
		ID: "QRO-GOSEC-G101-a-go-3", Title: "G101: Potential hardcoded credentials",
		Severity: finding.SeverityHigh, Status: finding.StatusReview,
		Target: &finding.Target{Type: "code", Identifier: "a.go:3"},
	})
	rep.Finish()
	data, _ := json.Marshal(rep)
	path := filepath.Join(t.TempDir(), "rapport.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdvisoryEcritLeBrouillon(t *testing.T) {
	out := filepath.Join(t.TempDir(), "brouillon.md")
	code, err := runAdvisory(writeReport(t), "QRO-GOSEC-G101-a-go-3", out)
	if err != nil || code != 0 {
		t.Fatalf("code %d, erreur %v", code, err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "**Location:** `a.go:3`") {
		t.Errorf("brouillon:\n%s", data)
	}
}

func TestAdvisoryConstatInconnu(t *testing.T) {
	if code, err := runAdvisory(writeReport(t), "QRO-RIEN", ""); err == nil || code != 2 {
		t.Errorf("code %d, erreur %v, attendu un refus", code, err)
	}
}

func TestAdvisoryRapportIllisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(path, []byte("pas du json"), 0o600)
	if code, err := runAdvisory(path, "", ""); err == nil || code != 2 {
		t.Errorf("code %d, erreur %v, attendu un refus", code, err)
	}
}
