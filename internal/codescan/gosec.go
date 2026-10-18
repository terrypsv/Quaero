// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// pre precede les arguments: les tests y placent ce qui fait du binaire
	// de test un faux gosec.
	pre []string
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

// Scan execute gosec sur chaque module Go du depot et normalise sa sortie. Les
// chemins sont ramenes au depot, pas au module. Un module en echec n'efface pas
// les autres, le rapport dit lequel manque. Si le delai tombe en route, ce qui
// est fini reste (voir deadlineScanner).
func (g Gosec) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	bin, err := resolveBin(g.bin())
	if err != nil {
		return nil, err
	}
	ctx = goWorkOff(ctx)
	mods, more := GoModules(dir)
	if len(mods) == 0 {
		mods = []string{"."}
	}
	var failed []string
	if len(mods) > MaxGoModules {
		mods = mods[:MaxGoModules]
		failed = append(failed, fmt.Sprintf("%d modules analyses au plus, les suivants non", MaxGoModules))
	}
	if more {
		failed = append(failed, "recherche des go.mod arretee, depot trop grand")
	}
	var out []finding.Finding
	ok := 0
	for i, m := range mods {
		// -fmt=json sur stdout, -quiet pour ne pas melanger du texte au JSON.
		args := append(append([]string{}, g.pre...), "-fmt=json", "-quiet", "./...")
		res, err := runTool(ctx, bin, moduleDir(dir, m), args...)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ok > 0 {
				for _, rest := range mods[i:] {
					failed = append(failed, orRoot(moduleLabel(rest))+": interrompu, delai maximal atteint")
				}
				break
			}
			return nil, err
		}
		if err := res.accept(0, 1); err != nil {
			failed = append(failed, orRoot(moduleLabel(m))+": "+err.Error())
			continue
		}
		fs, err := parseGosecAt(res.stdout, dir)
		if err != nil {
			failed = append(failed, orRoot(moduleLabel(m))+": "+err.Error())
			continue
		}
		ok++
		out = append(out, fs...)
	}
	if ok == 0 {
		return nil, fmt.Errorf("%s", strings.Join(failed, " ; "))
	}
	if len(failed) > 0 {
		out = append(out, partialScan("gosec", failed))
	}
	return out, nil
}

// handlesDeadline dit que gosec garde ce qui est fini quand le delai tombe.
func (Gosec) handlesDeadline() {}

// orRoot nomme la racine quand le module n'a pas d'autre nom.
func orRoot(label string) string {
	if label == "" {
		return "module racine"
	}
	return label
}

// interpretGosec lit le code de sortie avant le JSON. gosec sort en 1 des qu'il
// trouve une issue, ce n'est pas une panne. Tout autre code en est une.
func interpretGosec(res toolResult) ([]finding.Finding, error) {
	if err := res.accept(0, 1); err != nil {
		return nil, err
	}
	return parseGosecAt(res.stdout, res.root)
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

func parseGosec(raw []byte) ([]finding.Finding, error) { return parseGosecAt(raw, "") }

// parseGosecAt lit la sortie de gosec en ramenant chaque chemin sous root.
func parseGosecAt(raw []byte, root string) ([]finding.Finding, error) {
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
		iss.File = relTo(root, iss.File)
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
