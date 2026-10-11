// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Gosec orchestre gosec, l'analyseur statique de motifs non surs dans du code
// Go (appels crypto faibles, injection, permissions trop larges, erreurs
// ignorees). Contrairement a govulncheck, il ne parle pas de dependances mais
// de code ecrit ici: les deux couches se completent sans se recouvrir.
type Gosec struct {
	// Bin est le nom ou chemin du binaire. Vide, "gosec" est utilise.
	Bin string
}

func (g Gosec) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "gosec"
}

// Name identifie l'analyseur.
func (Gosec) Name() string { return "gosec" }

// Available dit si le binaire est trouvable dans le PATH.
func (g Gosec) Available() bool {
	_, err := resolveBin(g.bin())
	return err == nil
}

// Scan execute gosec sur dir et normalise sa sortie.
func (g Gosec) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	bin, err := resolveBin(g.bin())
	if err != nil {
		return nil, err
	}
	// -fmt=json sur stdout, -quiet pour ne pas melanger du texte au JSON.
	res, err := runTool(ctx, bin, dir, "-fmt=json", "-quiet", "./...")
	if err != nil {
		return nil, err
	}
	return interpretGosec(res)
}

// interpretGosec lit le code de sortie avant le JSON. gosec sort en 1 des qu'il
// trouve une issue, ce n'est pas une panne. Tout autre code en est une.
func interpretGosec(res toolResult) ([]finding.Finding, error) {
	if err := res.accept(0, 1); err != nil {
		return nil, err
	}
	return parseGosec(res.stdout)
}

// --- Schema de la sortie gosec -fmt=json ---

type gosecReport struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	RuleID     string   `json:"rule_id"`
	Details    string   `json:"details"`
	File       string   `json:"file"`
	Line       string   `json:"line"`
	Column     string   `json:"column"`
	Code       string   `json:"code"`
	CWE        gosecCWE `json:"cwe"`
}

type gosecCWE struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func parseGosec(raw []byte) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		// Pas de sortie: aucune issue. Ce n'est pas une erreur.
		return nil, nil
	}
	var rep gosecReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return nil, fmt.Errorf("sortie gosec illisible: %w", err)
	}

	var out []finding.Finding
	for _, iss := range rep.Issues {
		out = append(out, projectGosec(iss))
	}
	return out, nil
}

func projectGosec(iss gosecIssue) finding.Finding {
	loc := iss.File
	if iss.Line != "" {
		loc = fmt.Sprintf("%s:%s", iss.File, iss.Line)
	}

	out := finding.Finding{
		ID:          "QRO-GOSEC-" + iss.RuleID + "-" + sanitize(loc),
		Title:       iss.RuleID + ": " + iss.Details,
		Category:    Category,
		Severity:    gosecSeverity(iss.Severity),
		Status:      finding.StatusReview,
		Target:      &finding.Target{Type: "code", Identifier: loc},
		Observed:    fmt.Sprintf("%s (confiance %s)", iss.Details, strings.ToLower(iss.Confidence)),
		Remediation: "Revoir le motif signale et corriger ou justifier l'exception.",
		Declared:    finding.Bool(false),
	}
	if strings.TrimSpace(iss.Code) != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "code", Data: strings.TrimSpace(iss.Code)})
	}
	out.Evidence = append(out.Evidence, finding.Evidence{Type: "location", Data: loc})
	if iss.CWE.ID != "" {
		out.References = append(out.References, finding.Reference{
			Framework: "CWE",
			ID:        "CWE-" + iss.CWE.ID,
		})
	}
	return out
}

// gosecSeverity traduit l'echelle gosec (HIGH/MEDIUM/LOW) vers le schema. gosec
// ne descend pas sous low et n'emet pas de critical: le mapping est direct.
func gosecSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
