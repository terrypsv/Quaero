// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/terrypsv/Quaero/internal/finding"
)

// DefaultSemgrepConfig est le jeu de regles par defaut: la selection generale du
// registre semgrep, multi-langages, peu bruyante. La qualite d'un constat compte
// plus que leur nombre.
const DefaultSemgrepConfig = "p/default"

// Semgrep orchestre semgrep, un analyseur statique de motifs qui couvre la
// plupart des langages courants (Go, Python, JS/TS, Java, PHP, Ruby, C...). Il
// porte la couche "code ecrit ici" pour tout ce qui n'est pas Go, la ou gosec
// s'arrete au seul Go. C'est aussi le seul moteur capable de relever une faille
// encore inconnue: les autres ne retrouvent que des vulnerabilites publiees.
type Semgrep struct {
	// Bin est le nom ou chemin du binaire. Vide, "semgrep" est utilise.
	Bin string
	// Config est le jeu de regles. Vide, DefaultSemgrepConfig est utilise. Le
	// mode "auto" de semgrep est evite: il repose sur l'envoi de metriques.
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
	return DefaultSemgrepConfig
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
	// --metrics=off: par defaut semgrep envoie des metriques des que ses regles
	// viennent de son registre, dont une empreinte de l'adresse du projet. Quaero
	// n'envoie rien sur ce qu'il analyse.
	res, err := runTool(ctx, bin, dir,
		"scan", "--config", s.config(), "--metrics=off", "--json", "--quiet", dir)
	if err != nil {
		return nil, err
	}
	return interpretSemgrep(res)
}

// interpretSemgrep lit le code de sortie avant le JSON. Sans --error, semgrep
// sort en 0 meme quand il trouve quelque chose; 1 est accepte par prudence,
// tout autre code est une panne.
func interpretSemgrep(res toolResult) ([]finding.Finding, error) {
	if err := res.accept(0, 1); err != nil {
		return nil, err
	}
	return parseSemgrepAt(res.stdout, res.root)
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

func parseSemgrep(raw []byte) ([]finding.Finding, error) { return parseSemgrepAt(raw, "") }

// parseSemgrepAt lit la sortie de semgrep en ramenant chaque chemin sous root.
func parseSemgrepAt(raw []byte, root string) ([]finding.Finding, error) {
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
		r.Path = relTo(root, r.Path)
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
		Title:       rule + ": " + shortMessage(r.Extra.Message),
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
	// L'identifiant complet de la regle est celui qu'attend une annotation
	// nosemgrep: le titre n'en garde que la fin, lisible mais insuffisant.
	if r.CheckID != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: "rule", Data: r.CheckID})
	}
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

// shortMessage garde la premiere phrase d'un message semgrep, souvent long de
// trois ou quatre phrases, pour un titre qui se lit d'un coup d'oeil. Le
// message entier reste dans la description.
func shortMessage(s string) string {
	s = firstLine(s)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	const most = 110
	if len(s) <= most {
		return s
	}
	cut := strings.LastIndexByte(s[:most], ' ')
	if cut < most/2 {
		cut = most
		// Pas de coupe au milieu d'un caractere accentue.
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
	}
	return strings.TrimRight(s[:cut], " ,;:") + "..."
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
