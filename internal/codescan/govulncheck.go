// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Govulncheck orchestre l'outil officiel du projet Go. Il croise les
// dependances du depot avec la base de vulnerabilites Go et, surtout, dit si le
// symbole vulnerable est *atteignable* depuis le code analyse. C'est cette
// distinction qui fait sa valeur: une dependance vulnerable jamais appelee est
// un bruit, un symbole vulnerable atteint est un constat.
type Govulncheck struct {
	// Bin est le nom ou chemin du binaire. Vide, "govulncheck" est utilise.
	Bin string
}

func (g Govulncheck) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "govulncheck"
}

// Name identifie l'analyseur.
func (Govulncheck) Name() string { return "govulncheck" }

// Available dit si le binaire est trouvable dans le PATH.
func (g Govulncheck) Available() bool {
	_, err := exec.LookPath(g.bin())
	return err == nil
}

// Scan execute govulncheck sur dir et normalise sa sortie.
func (g Govulncheck) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	// -json rend un flux d'objets; -C fixe le dossier de travail sans dependre
	// du cwd du processus appelant. On vise tout le module.
	cmd := exec.CommandContext(ctx, g.bin(), "-json", "-C", dir, "./...")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// govulncheck sort en code non nul des qu'il trouve une vulnerabilite: ce
	// n'est pas une erreur d'execution. On ne traite comme erreur que l'absence
	// de sortie JSON exploitable.
	runErr := cmd.Run()

	fs, parseErr := parseGovulncheck(stdout.Bytes())
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, parseErr
	}
	return fs, nil
}

// --- Schema du flux govulncheck -json ---
//
// Le flux est une suite d'objets JSON concatenes, chacun portant exactement un
// des champs ci-dessous. Les "osv" definissent les vulnerabilites; les
// "finding" rattachent une vulnerabilite a une trace d'appel dans le code.

type gvcMessage struct {
	OSV     *gvcOSV     `json:"osv"`
	Finding *gvcFinding `json:"finding"`
}

type gvcOSV struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	References []gvcReference `json:"references"`
}

type gvcReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type gvcFinding struct {
	OSV          string     `json:"osv"`
	FixedVersion string     `json:"fixed_version"`
	Trace        []gvcFrame `json:"trace"`
}

type gvcFrame struct {
	Module   string       `json:"module"`
	Version  string       `json:"version"`
	Package  string       `json:"package"`
	Function string       `json:"function"`
	Position *gvcPosition `json:"position"`
}

type gvcPosition struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// reachable: un constat dont la premiere frame porte une fonction et une
// position est un symbole vulnerable effectivement appele.
func (f gvcFinding) reachable() bool {
	return len(f.Trace) > 0 && f.Trace[0].Function != "" && f.Trace[0].Position != nil
}

// parseGovulncheck lit le flux et produit un constat par vulnerabilite. Pour une
// meme vulnerabilite, govulncheck emet plusieurs "finding" de specificite
// croissante (module, paquet, symbole); on retient le plus specifique.
func parseGovulncheck(raw []byte) ([]finding.Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))

	osvByID := map[string]gvcOSV{}
	bestByOSV := map[string]gvcFinding{}

	for {
		var msg gvcMessage
		if err := dec.Decode(&msg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("flux govulncheck illisible: %w", err)
		}
		switch {
		case msg.OSV != nil:
			osvByID[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			id := msg.Finding.OSV
			prev, seen := bestByOSV[id]
			if !seen || moreSpecific(*msg.Finding, prev) {
				bestByOSV[id] = *msg.Finding
			}
		}
	}

	ids := make([]string, 0, len(bestByOSV))
	for id := range bestByOSV {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []finding.Finding
	for _, id := range ids {
		out = append(out, projectVuln(osvByID[id], bestByOSV[id]))
	}
	return out, nil
}

// moreSpecific prefere une trace atteignable, puis la plus longue.
func moreSpecific(a, b gvcFinding) bool {
	if a.reachable() != b.reachable() {
		return a.reachable()
	}
	return len(a.Trace) > len(b.Trace)
}

func projectVuln(osv gvcOSV, f gvcFinding) finding.Finding {
	reach := f.reachable()

	severity := finding.SeverityMedium
	if reach {
		severity = finding.SeverityHigh
	}

	title := osv.Summary
	if title == "" {
		title = osv.ID
	}

	out := finding.Finding{
		ID:          "QRO-VULN-" + sanitize(osv.ID),
		Title:       title,
		Description: osv.Details,
		Category:    Category,
		Severity:    severity,
		Status:      finding.StatusReview,
		Target:      &finding.Target{Type: "code", Identifier: topModule(f)},
		Observed:    observedVuln(reach, f),
		Remediation: remediationVuln(f.FixedVersion),
		Declared:    finding.Bool(false),
	}

	if len(f.Trace) > 0 && f.Trace[0].Position != nil {
		p := f.Trace[0].Position
		out.Evidence = append(out.Evidence, finding.Evidence{
			Type: "location",
			Data: fmt.Sprintf("%s:%d", p.Filename, p.Line),
		})
	}
	for _, ref := range osv.References {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "url", Data: ref.URL})
	}

	// OSV d'abord, puis les alias publics (CVE, GHSA) tels quels: c'est le
	// numero que l'operateur citera dans une divulgation.
	out.References = append(out.References, finding.Reference{Framework: "OSV", ID: osv.ID})
	for _, a := range osv.Aliases {
		out.References = append(out.References, finding.Reference{Framework: aliasFramework(a), ID: a})
	}

	return out
}

func observedVuln(reach bool, f gvcFinding) string {
	if reach {
		fr := f.Trace[0]
		loc := ""
		if fr.Position != nil {
			loc = fmt.Sprintf(" (%s:%d)", fr.Position.Filename, fr.Position.Line)
		}
		return fmt.Sprintf("symbole vulnerable atteignable: %s%s", fr.Function, loc)
	}
	return fmt.Sprintf("dependance vulnerable importee: %s", topModule(f))
}

func remediationVuln(fixed string) string {
	if fixed != "" {
		return "Mettre a jour la dependance vers " + fixed + " ou plus recent."
	}
	return "Aucune version corrigee publiee: isoler ou remplacer la dependance."
}

// topModule rend le module le plus haut de la trace, celui que l'operateur doit
// mettre a jour. La trace va du symbole vulnerable vers l'exterieur; le dernier
// cadre portant un module est la dependance a corriger.
func topModule(f gvcFinding) string {
	for i := range f.Trace {
		if m := f.Trace[i].Module; m != "" {
			v := f.Trace[i].Version
			if v != "" {
				return m + "@" + v
			}
			return m
		}
	}
	return "module inconnu"
}

func aliasFramework(alias string) string {
	switch {
	case strings.HasPrefix(alias, "CVE-"):
		return "CVE"
	case strings.HasPrefix(alias, "GHSA-"):
		return "GHSA"
	default:
		return "alias"
	}
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "-", ":", "-", " ", "-", ".", "-").Replace(s)
}
