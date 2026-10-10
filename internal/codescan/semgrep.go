// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Semgrep orchestre semgrep, un analyseur statique de motifs qui couvre la
// plupart des langages courants (Go, Python, JS/TS, Java, PHP, Ruby, C...). Il
// porte la couche "code ecrit ici" pour tout ce qui n'est pas Go, la ou gosec
// s'arrete au seul Go.
type Semgrep struct {
	// Bin est le nom ou chemin du binaire. Vide, "semgrep" est utilise.
	Bin string
	// Config est le jeu de regles. Vide, "auto" laisse semgrep choisir selon les
	// langages detectes.
	Config string
}

func (s Semgrep) bin() string {
	if s.Bin != "" {
		return s.Bin
	}
	return "semgrep"
}

func (s Semgrep) config() string {
	if s.Config != "" {
		return s.Config
	}
	return "auto"
}

// Name identifie l'analyseur.
func (Semgrep) Name() string { return "semgrep" }

// Available dit si le binaire est trouvable dans le PATH.
func (s Semgrep) Available() bool {
	_, err := resolveBin(s.bin())
	return err == nil
}

// Scan execute semgrep sur dir et normalise sa sortie.
func (s Semgrep) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	bin, err := resolveBin(s.bin())
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin,
		"--config", s.config(), "--json", "--quiet", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	fs, parseErr := parseSemgrep(stdout.Bytes())
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, parseErr
	}
	return fs, nil
}

// --- Schema de la sortie semgrep --json ---

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Lines    string          `json:"lines"`
	Metadata semgrepMetadata `json:"metadata"`
}

type semgrepMetadata struct {
	// CWE est tantot une chaine, tantot une liste de chaines selon la regle.
	CWE        json.RawMessage `json:"cwe"`
	References []string        `json:"references"`
}

func parseSemgrep(raw []byte) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var rep semgrepReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return nil, fmt.Errorf("sortie semgrep illisible: %w", err)
	}

	var out []finding.Finding
	for _, r := range rep.Results {
		out = append(out, projectSemgrep(r))
	}
	return out, nil
}

func projectSemgrep(r semgrepResult) finding.Finding {
	loc := r.Path
	if r.Start.Line > 0 {
		loc = fmt.Sprintf("%s:%d", r.Path, r.Start.Line)
	}
	rule := shortRule(r.CheckID)

	out := finding.Finding{
		ID:          "QRO-SEMGREP-" + sanitize(rule) + "-" + sanitize(loc),
		Title:       rule + ": " + firstLine(r.Extra.Message),
		Description: r.Extra.Message,
		Category:    Category,
		Severity:    semgrepSeverity(r.Extra.Severity),
		Status:      finding.StatusReview,
		Target:      &finding.Target{Type: "code", Identifier: loc},
		Observed:    firstLine(r.Extra.Message),
		Remediation: "Revoir le motif signale et corriger ou justifier l'exception.",
		Declared:    finding.Bool(false),
	}
	if code := strings.TrimSpace(r.Extra.Lines); code != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "code", Data: code})
	}
	out.Evidence = append(out.Evidence, finding.Evidence{Type: "location", Data: loc})
	for _, cwe := range cweList(r.Extra.Metadata.CWE) {
		out.References = append(out.References, finding.Reference{Framework: "CWE", ID: cwe})
	}
	return out
}

// semgrepSeverity traduit l'echelle semgrep (ERROR/WARNING/INFO) vers le schema.
func semgrepSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return finding.SeverityHigh
	case "WARNING":
		return finding.SeverityMedium
	case "INFO":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// cweList normalise le champ cwe, chaine ou liste, et en extrait les
// identifiants "CWE-nnn" tels qu'ils sont ecrits ("CWE-79: ..." garde "CWE-79").
func cweList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{cweID(one)}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		out := make([]string, 0, len(many))
		for _, c := range many {
			out = append(out, cweID(c))
		}
		return out
	}
	return nil
}

func cweID(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// shortRule garde le dernier segment d'un check_id souvent tres long
// (ex. "python.lang.security.audit.dangerous-exec" -> "dangerous-exec").
func shortRule(id string) string {
	if i := strings.LastIndexByte(id, '.'); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
