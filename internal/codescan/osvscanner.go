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

// OSVScanner orchestre osv-scanner (OpenSSF), qui croise les dependances
// declarees d'un depot avec la base OSV, tous ecosystemes confondus (npm, PyPI,
// Go, Maven, crates, Composer...). Il porte la couche "dependances vulnerables"
// pour les langages que govulncheck ne couvre pas.
//
// A la difference de govulncheck, il ne fait pas d'analyse d'atteignabilite: il
// signale qu'une dependance vulnerable est declaree, pas que le code fautif est
// appele. Les constats sortent donc en gravite medium par defaut.
type OSVScanner struct {
	// Bin est le nom ou chemin du binaire. Vide, "osv-scanner" est utilise.
	Bin string
}

func (o OSVScanner) bin() string {
	if o.Bin != "" {
		return o.Bin
	}
	return "osv-scanner"
}

// Name identifie l'analyseur.
func (OSVScanner) Name() string { return "osv-scanner" }

// Available dit si le binaire est trouvable dans le PATH.
func (o OSVScanner) Available() bool {
	_, err := exec.LookPath(o.bin())
	return err == nil
}

// Scan execute osv-scanner sur dir et normalise sa sortie.
func (o OSVScanner) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	cmd := exec.CommandContext(ctx, o.bin(), "--format", "json", "-r", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	fs, parseErr := parseOSV(stdout.Bytes())
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, parseErr
	}
	return fs, nil
}

// --- Schema de la sortie osv-scanner --format json ---

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
}

type osvPackage struct {
	Package         osvPkgInfo `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	References []osvReference `json:"references"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func parseOSV(raw []byte) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var rep osvReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return nil, fmt.Errorf("sortie osv-scanner illisible: %w", err)
	}

	var out []finding.Finding
	for _, res := range rep.Results {
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				out = append(out, projectOSV(res.Source, pkg.Package, v))
			}
		}
	}
	return out, nil
}

func projectOSV(src osvSource, pkg osvPkgInfo, v osvVuln) finding.Finding {
	title := v.Summary
	if title == "" {
		title = v.ID
	}
	dep := pkg.Name
	if pkg.Version != "" {
		dep = pkg.Name + "@" + pkg.Version
	}

	out := finding.Finding{
		ID:          "QRO-OSV-" + sanitize(v.ID) + "-" + sanitize(pkg.Name),
		Title:       title,
		Description: v.Details,
		Category:    Category,
		// Pas d'atteignabilite ici: dependance vulnerable declaree, gravite
		// medium par defaut. govulncheck releve le Go atteignable a high.
		Severity:    finding.SeverityMedium,
		Status:      finding.StatusReview,
		Target:      &finding.Target{Type: "dependency", Identifier: dep},
		Observed:    fmt.Sprintf("dependance vulnerable declaree: %s (%s)", dep, pkg.Ecosystem),
		Remediation: "Mettre a jour la dependance vers une version corrigee, ou la remplacer.",
		Declared:    finding.Bool(false),
	}
	if src.Path != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "manifest", Data: src.Path})
	}
	for _, ref := range v.References {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "url", Data: ref.URL})
	}
	out.References = append(out.References, finding.Reference{Framework: "OSV", ID: v.ID})
	for _, a := range v.Aliases {
		out.References = append(out.References, finding.Reference{Framework: aliasFramework(a), ID: a})
	}
	return out
}
