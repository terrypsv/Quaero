// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
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
	_, err := resolveBin(o.bin())
	return err == nil
}

// Scan execute osv-scanner sur dir et normalise sa sortie.
func (o OSVScanner) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	bin, err := resolveBin(o.bin())
	if err != nil {
		return nil, err
	}
	res, err := runTool(ctx, bin, dir, "--format", "json", "-r", dir)
	if err != nil {
		return nil, err
	}
	return interpretOSV(res)
}

// interpretOSV lit le code de sortie avant le JSON. 0 rien de vulnerable, 1 des
// vulnerabilites trouvees, 128 aucune dependance a verifier, le reste une panne.
// Le cas 128 ne doit jamais ressortir comme un depot sain: rien n'a ete verifie.
func interpretOSV(res toolResult) ([]finding.Finding, error) {
	if res.exitCode == 128 {
		return []finding.Finding{nothingToCheck("osv-scanner",
			"aucun manifeste de dependances reconnu, rien n'a pu etre verifie",
			"Normal pour un depot sans dependances declarees. Sinon, verifier que les manifestes et fichiers de verrouillage sont bien versionnes.")}, nil
	}
	if err := res.accept(0, 1); err != nil {
		return nil, err
	}
	return parseOSVAt(res.stdout, res.root)
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
	Affected   []osvAffected  `json:"affected"`
}

// osvAffected dit quelles versions d'un paquet une vulnerabilite touche, et a
// partir de laquelle elle est corrigee.
type osvAffected struct {
	Package osvPkgInfo `json:"package"`
	Ranges  []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
}

// span est un intervalle de versions touchees: de introduced, compris, a
// fixed, exclu, ou a last, compris. Sans l'un ni l'autre, il reste ouvert.
type span struct{ introduced, fixed, last string }

func (s span) holds(v string, cmp func(a, b string) int) bool {
	if s.introduced != "" && s.introduced != "0" && cmp(v, s.introduced) < 0 {
		return false
	}
	switch {
	case s.fixed != "":
		return cmp(v, s.fixed) < 0
	case s.last != "":
		return cmp(v, s.last) <= 0
	}
	return true
}

// fixedFor rend la premiere version corrigee de pkg qui depasse sa version
// courante et n'est elle-meme dans aucun intervalle touche, comme
// govulncheck, ou "". known dit que la base decrit ce paquet: sans cela,
// l'absence de version corrigee ne veut rien dire. Les intervalles GIT
// portent des commits, pas des versions: ils ne comptent pas.
func (v osvVuln) fixedFor(pkg osvPkgInfo) (fixed string, known bool) {
	var spans []span
	var fixes []string
	for _, a := range v.Affected {
		if normName(pkg.Ecosystem, a.Package.Name) != normName(pkg.Ecosystem, pkg.Name) ||
			(a.Package.Ecosystem != "" && pkg.Ecosystem != "" && !strings.EqualFold(a.Package.Ecosystem, pkg.Ecosystem)) {
			continue
		}
		for _, r := range a.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			known = true
			open := -1 // l'intervalle que le prochain evenement referme
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					spans = append(spans, span{introduced: e.Introduced})
					open = len(spans) - 1
				case e.Fixed != "":
					fixes = append(fixes, e.Fixed)
					if open >= 0 {
						spans[open].fixed, open = e.Fixed, -1
					}
				case e.LastAffected != "":
					if open >= 0 {
						spans[open].last, open = e.LastAffected, -1
					}
				}
			}
		}
	}
	cmp := versionCmp(pkg.Ecosystem)
	sort.Slice(fixes, func(i, j int) bool { return cmp(fixes[i], fixes[j]) < 0 })
	for _, f := range fixes {
		if pkg.Version != "" && cmp(f, pkg.Version) <= 0 {
			continue
		}
		touched := false
		for _, s := range spans {
			touched = touched || s.holds(f, cmp)
		}
		if !touched {
			return f, known
		}
	}
	return "", known
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func parseOSV(raw []byte) ([]finding.Finding, error) { return parseOSVAt(raw, "") }

// parseOSVAt lit la sortie d'osv-scanner en ramenant chaque manifeste sous root.
func parseOSVAt(raw []byte, root string) ([]finding.Finding, error) {
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
		res.Source.Path = relTo(root, res.Source.Path)
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
	if pkg.Ecosystem != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceEcosystem, Data: pkg.Ecosystem})
	}
	// Sans description du paquet dans la base, la version corrigee reste
	// inconnue: le conseil general reste.
	switch fixed, known := v.fixedFor(pkg); {
	case fixed != "":
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceFixedIn, Data: strings.TrimPrefix(fixed, "v")})
		out.Remediation = "Mettre a jour vers " + strings.TrimPrefix(fixed, "v") + " ou plus recent."
	case known:
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceNoFix, Data: "oui"})
		out.Remediation = "Aucune version corrigee publiee: isoler ou remplacer la dependance."
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
