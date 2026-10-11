// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

func TestParseSemgrepCWEString(t *testing.T) {
	// cwe en chaine simple, severite ERROR -> high.
	raw := []byte(`{"results":[
{"check_id":"python.lang.security.audit.dangerous-exec","path":"app.py","start":{"line":12,"col":1},"extra":{"message":"Detected exec() with user input","severity":"ERROR","lines":"exec(data)","metadata":{"cwe":"CWE-95: Improper Neutralization","references":["https://owasp.org"]}}}
]}`)
	fs, err := parseSemgrep(raw)
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
	if f.Target == nil || f.Target.Identifier != "app.py:12" {
		t.Errorf("cible = %+v, attendu app.py:12", f.Target)
	}
	if !hasRef(f.References, "CWE", "CWE-95") {
		t.Error("reference CWE-95 manquante")
	}
	// L'identifiant complet reste disponible pour une annotation nosemgrep.
	full := false
	for _, e := range f.Evidence {
		if e.Type == "rule" && e.Data == "python.lang.security.audit.dangerous-exec" {
			full = true
		}
	}
	if !full {
		t.Error("identifiant complet de la regle absent des preuves")
	}
}

func TestParseSemgrepCWEList(t *testing.T) {
	// cwe en liste, severite WARNING -> medium.
	raw := []byte(`{"results":[
{"check_id":"go.lang.security.audit.xss","path":"h.go","start":{"line":3,"col":1},"extra":{"message":"XSS","severity":"WARNING","lines":"w.Write(x)","metadata":{"cwe":["CWE-79: XSS","CWE-80: Basic XSS"]}}}
]}`)
	fs, err := parseSemgrep(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(fs))
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Errorf("severite = %q, attendu medium", fs[0].Severity)
	}
	if !hasRef(fs[0].References, "CWE", "CWE-79") || !hasRef(fs[0].References, "CWE", "CWE-80") {
		t.Error("references CWE multiples manquantes")
	}
}

func TestParseSemgrepEmpty(t *testing.T) {
	fs, err := parseSemgrep([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("constats = %d, attendu 0", len(fs))
	}
}

func TestParseOSV(t *testing.T) {
	raw := []byte(`{"results":[
{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[
{"package":{"name":"lodash","version":"4.17.4","ecosystem":"npm"},"vulnerabilities":[
{"id":"GHSA-jf85-cpcp-j695","summary":"Prototype pollution in lodash","details":"d","aliases":["CVE-2019-10744"],"references":[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-jf85-cpcp-j695"}]}
]}
]}
]}`)
	fs, err := parseOSV(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(fs))
	}
	f := fs[0]
	// Pas d'atteignabilite: medium.
	if f.Severity != finding.SeverityMedium {
		t.Errorf("severite = %q, attendu medium", f.Severity)
	}
	if f.Target == nil || f.Target.Type != "dependency" || f.Target.Identifier != "lodash@4.17.4" {
		t.Errorf("cible = %+v, attendu dependency lodash@4.17.4", f.Target)
	}
	if !hasRef(f.References, "OSV", "GHSA-jf85-cpcp-j695") {
		t.Error("reference OSV manquante")
	}
	if !hasRef(f.References, "CVE", "CVE-2019-10744") {
		t.Error("alias CVE non remonte")
	}
}

func TestParseOSVEmpty(t *testing.T) {
	fs, err := parseOSV([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("constats = %d, attendu 0", len(fs))
	}
}
