// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
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
	// pre precede les arguments: les tests y placent ce qui fait du binaire
	// de test un faux govulncheck.
	pre []string
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
	_, err := resolveBin(g.bin())
	return err == nil
}

// goSystem est un systeme pour lequel govulncheck compile le depot.
type goSystem struct {
	goos, goarch, label string
	// native: le systeme de la machine, analyse sans rien changer a
	// l'environnement, cgo compris, comme avant l'analyse par systeme.
	native bool
}

// crossSystems sont les systemes que vise un outil Go multiplateforme. Un depot
// n'y compile pas le meme code: analyse sous Windows seulement, govulncheck ne
// voit pas ce que seul le build Linux appelle, et « non appele » mentirait.
var crossSystems = []goSystem{
	{goos: "linux", goarch: "amd64", label: "Linux"},
	{goos: "darwin", goarch: "arm64", label: "macOS"},
	{goos: "windows", goarch: "amd64", label: "Windows"},
}

// systemsFor rend les systemes a analyser depuis une machine host: elle d'abord,
// telle quelle, puis les autres en compilation croisee. Si le delai tombe en
// route, c'est l'analyse de la machine, celle d'avant, qui est deja faite.
func systemsFor(host string) []goSystem {
	label := host
	var rest []goSystem
	for _, s := range crossSystems {
		if s.goos == host {
			label = s.label
			continue
		}
		rest = append(rest, s)
	}
	return append([]goSystem{{goos: host, goarch: runtime.GOARCH, label: label, native: true}}, rest...)
}

// env attache a ctx ce qui fait compiler govulncheck pour ce systeme. GOOS et
// GOARCH sont toujours fixes: un GOOS=windows exporte sous Linux ferait sinon
// passer Windows pour la machine. Hors de la machine, cgo est coupe: un
// compilateur C ne sait pas viser un autre systeme, et un CGO_ENABLED=1 de
// l'utilisateur ferait echouer l'analyse. Sur la machine, cgo reste tel quel.
func (s goSystem) env(ctx context.Context) context.Context {
	if s.native {
		return withExtraEnv(ctx, "GOOS="+s.goos, "GOARCH="+s.goarch)
	}
	return withExtraEnv(ctx, "GOOS="+s.goos, "GOARCH="+s.goarch, "CGO_ENABLED=0")
}

// goFacts est ce que le moteur Go apprend du depot en plus de ses constats.
type goFacts struct {
	// goVersion est la version de Go qui a compile, pas celle du go.mod.
	goVersion string
	// unused porte les modules du go.mod qu'aucun paquet du depot n'importe,
	// tests compris, quels que soient le systeme et les tags (voir build.go).
	// nil si la question n'a pas pu etre posee.
	unused map[string]bool
}

// Scan execute govulncheck sur dir et normalise sa sortie.
func (g Govulncheck) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	fs, _, err := g.ScanBuild(ctx, dir)
	return fs, err
}

// ScanBuild execute govulncheck pour chaque systeme, fusionne les constats et
// rend aussi ce qu'il a appris du depot.
//
// Un systeme en echec n'annule pas les autres, le rapport dit lequel manque.
// Hors de la machine, c'est le plus souvent un depot qui ne vise pas ce
// systeme. Un systeme sans rien a compiler n'est pas un echec. Le delai du
// moteur couvre tous les systemes: s'il tombe, ce qui est fini reste.
func (g Govulncheck) ScanBuild(ctx context.Context, dir string) ([]finding.Finding, *goFacts, error) {
	bin, err := resolveBin(g.bin())
	if err != nil {
		return nil, nil, err
	}
	facts := &goFacts{}
	systems := systemsFor(runtime.GOOS)
	var runs []gvcRun
	var failed []string
	for i, sys := range systems {
		// -json rend un flux d'objets; -C fixe le dossier de travail sans
		// dependre du cwd du processus appelant. On vise tout le module.
		args := append(append([]string{}, g.pre...), "-json", "-C", dir, "./...")
		res, err := runTool(sys.env(ctx), bin, dir, args...)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && len(runs) > 0 {
				for _, rest := range systems[i:] {
					failed = append(failed, rest.label+": interrompu, delai maximal atteint")
				}
				break
			}
			// Demarrage impossible, annulation, ou rien d'analyse a temps.
			return nil, nil, err
		}
		if nothingToBuild(res) {
			continue
		}
		run, err := interpretGovulncheckRun(res)
		if err != nil {
			failed = append(failed, sys.label+": "+err.Error())
			continue
		}
		run.system = sys.label
		if facts.goVersion == "" && run.sbom != nil {
			facts.goVersion = run.sbom.GoVersion
		}
		runs = append(runs, run)
	}
	if len(runs) == 0 && len(failed) > 0 {
		return nil, nil, fmt.Errorf("%s", strings.Join(failed, " ; "))
	}
	// go mod why vient apres les analyses: il ne lit que le graphe des
	// modules, c'est rapide, et un delai qui tombe ne coute pas l'analyse de
	// la machine.
	if ctx.Err() == nil {
		facts.unused = unusedModules(ctx, dir)
	}
	if len(runs) == 0 {
		return []finding.Finding{nothingToCheck("govulncheck",
			"aucun paquet Go a compiler pour Linux, macOS ni Windows",
			"Verifier que le depot contient du code Go hors des tests.")}, facts, nil
	}
	fs := mergeRuns(runs)
	if len(failed) > 0 {
		fs = append(fs, partialScan("govulncheck", failed))
	}
	return fs, facts, nil
}

// nothingToBuild reconnait govulncheck qui ne trouve aucun paquet a compiler
// pour ce systeme: tous les fichiers en sont exclus par leurs contraintes de
// build. Ce n'est pas une panne, ce systeme n'a simplement rien a analyser. Le
// message vient en dernier, apres d'eventuels telechargements de modules.
func nothingToBuild(res toolResult) bool {
	const msg = "no packages matched"
	return res.exitCode != 0 && (strings.Contains(res.stderr, msg) || strings.Contains(res.stderrTail, msg))
}

// interpretGovulncheck lit le code de sortie avant le flux. En mode -json,
// govulncheck sort en 0 quel que soit le nombre de vulnerabilites trouvees:
// tout autre code est une panne, meme si un debut de flux a ete ecrit.
func interpretGovulncheck(res toolResult) ([]finding.Finding, error) {
	run, err := interpretGovulncheckRun(res)
	if err != nil {
		return nil, err
	}
	return mergeRuns([]gvcRun{run}), nil
}

func interpretGovulncheckRun(res toolResult) (gvcRun, error) {
	if err := res.accept(0); err != nil {
		return gvcRun{}, err
	}
	return readGovulncheck(res.stdout)
}

// --- Schema du flux govulncheck -json ---
//
// Le flux est une suite d'objets JSON concatenes, chacun portant exactement un
// des champs ci-dessous. Les "osv" definissent les vulnerabilites; les
// "finding" rattachent une vulnerabilite a une trace d'appel dans le code.

type gvcMessage struct {
	OSV     *gvcOSV     `json:"osv"`
	Finding *gvcFinding `json:"finding"`
	SBOM    *gvcSBOM    `json:"SBOM"`
}

// gvcSBOM decrit ce que govulncheck a compile. Seule la version de Go sert:
// osv-scanner lit celle du go.mod, souvent plus ancienne.
type gvcSBOM struct {
	GoVersion string `json:"go_version"`
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

// gvcRun est ce qu'une execution de govulncheck a rendu, pour un systeme.
type gvcRun struct {
	system string
	osvs   map[string]gvcOSV
	best   map[string]gvcFinding
	sbom   *gvcSBOM
}

// parseGovulncheck lit le flux d'une execution et produit un constat par
// vulnerabilite.
func parseGovulncheck(raw []byte) ([]finding.Finding, error) {
	run, err := readGovulncheck(raw)
	if err != nil {
		return nil, err
	}
	return mergeRuns([]gvcRun{run}), nil
}

// readGovulncheck lit le flux. Pour une meme vulnerabilite, govulncheck emet
// plusieurs "finding" de specificite croissante (module, paquet, symbole); on
// retient le plus specifique.
func readGovulncheck(raw []byte) (gvcRun, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	run := gvcRun{osvs: map[string]gvcOSV{}, best: map[string]gvcFinding{}}
	for {
		var msg gvcMessage
		if err := dec.Decode(&msg); err == io.EOF {
			break
		} else if err != nil {
			return gvcRun{}, fmt.Errorf("flux govulncheck illisible: %w", err)
		}
		switch {
		case msg.OSV != nil:
			run.osvs[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			id := msg.Finding.OSV
			prev, seen := run.best[id]
			if !seen || moreSpecific(*msg.Finding, prev) {
				run.best[id] = *msg.Finding
			}
		case msg.SBOM != nil:
			run.sbom = msg.SBOM
		}
	}
	return run, nil
}

// mergeRuns fusionne les executions par vulnerabilite: la trace la plus
// specifique l'emporte, et le constat dit sous quels systemes le code fautif
// est appele.
func mergeRuns(runs []gvcRun) []finding.Finding {
	osvByID := map[string]gvcOSV{}
	best := map[string]gvcFinding{}
	reachOn := map[string][]string{}
	for _, r := range runs {
		for id, o := range r.osvs {
			osvByID[id] = o
		}
		for id, f := range r.best {
			prev, seen := best[id]
			if !seen || moreSpecific(f, prev) {
				best[id] = f
			}
			if f.reachable() && r.system != "" {
				reachOn[id] = append(reachOn[id], r.system)
			}
		}
	}

	ids := make([]string, 0, len(best))
	for id := range best {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []finding.Finding
	for _, id := range ids {
		var systems []string
		// Les systemes ne se nomment que s'ils different: appele partout, la
		// precision n'apporte rien.
		if len(reachOn[id]) < len(runs) {
			systems = reachOn[id]
		}
		out = append(out, projectVuln(osvByID[id], best[id], systems))
	}
	return out
}

// moreSpecific prefere une trace atteignable, puis la plus longue.
func moreSpecific(a, b gvcFinding) bool {
	if a.reachable() != b.reachable() {
		return a.reachable()
	}
	return len(a.Trace) > len(b.Trace)
}

func projectVuln(osv gvcOSV, f gvcFinding, systems []string) finding.Finding {
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
		Observed:    observedVuln(reach, f, systems),
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

	// Pre-tri: govulncheck est le seul moteur qui sait si le code fautif est
	// appele. Son avis voyage avec le constat (pretri.go).
	if reach {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceContext, Data: ContextCalled})
	} else {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceContext, Data: ContextNotCalled})
	}

	// OSV d'abord, puis les alias publics (CVE, GHSA) tels quels: c'est le
	// numero que l'operateur citera dans une divulgation.
	out.References = append(out.References, finding.Reference{Framework: "OSV", ID: osv.ID})
	for _, a := range osv.Aliases {
		out.References = append(out.References, finding.Reference{Framework: aliasFramework(a), ID: a})
	}

	return out
}

func observedVuln(reach bool, f gvcFinding, systems []string) string {
	if reach {
		fr := f.Trace[0]
		loc := ""
		if fr.Position != nil {
			loc = fmt.Sprintf(" (%s:%d)", fr.Position.Filename, fr.Position.Line)
		}
		where := ""
		if len(systems) > 0 {
			where = " sous " + joinFr(systems)
		}
		return fmt.Sprintf("symbole vulnerable atteignable%s: %s%s", where, fr.Function, loc)
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

// joinFr ecrit une liste a la francaise: « Linux », « Linux et macOS »,
// « Linux, macOS et Windows ».
func joinFr(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " et " + items[len(items)-1]
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
	return strings.NewReplacer("/", "-", `\`, "-", ":", "-", " ", "-", ".", "-").Replace(s)
}
