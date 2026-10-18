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
	// unused porte, par go.mod du depot (« go.mod », « cmd/x/go.mod »), les
	// modules requis qu'aucun paquet n'importe, tests compris, quels que
	// soient le systeme et les tags (voir build.go). Un go.mod absent de la
	// carte n'a pas pu etre interroge.
	unused map[string]map[string]bool
}

// Scan execute govulncheck sur dir et normalise sa sortie.
func (g Govulncheck) Scan(ctx context.Context, dir string) ([]finding.Finding, error) {
	fs, _, err := g.ScanBuild(ctx, dir)
	return fs, err
}

// ScanBuild execute govulncheck pour chaque module Go du depot et chaque
// systeme, fusionne les constats et rend aussi ce qu'il a appris du depot.
//
// Un module ou un systeme en echec n'annule pas les autres, le rapport dit
// lequel manque. Hors de la machine, c'est le plus souvent un depot qui ne vise
// pas ce systeme. Un systeme sans rien a compiler n'est pas un echec. Le delai
// du moteur couvre tout: s'il tombe, ce qui est fini reste.
func (g Govulncheck) ScanBuild(ctx context.Context, dir string) ([]finding.Finding, *goFacts, error) {
	bin, err := resolveBin(g.bin())
	if err != nil {
		return nil, nil, err
	}
	ctx = goWorkOff(ctx)
	all, more := GoModules(dir)
	// Les modules d'exemple, de test ou de code tiers ne sont pas livres: un
	// appel au code fautif y ferait passer la faille pour appelee.
	var mods []string
	for _, m := range all {
		if !offProductModule(m) {
			mods = append(mods, m)
		}
	}
	switch {
	case len(all) == 0:
		mods = []string{"."}
	case len(mods) == 0:
		return []finding.Finding{nothingToCheck("govulncheck",
			"seuls des modules d'exemple, de test ou de code tiers: "+strings.Join(all, ", "),
			"Ces modules ne sont pas livres, leurs dependances restent dans la liste d'osv-scanner.")}, nil, nil
	}
	capped := len(mods) > MaxGoModules
	if capped {
		mods = mods[:MaxGoModules]
	}
	facts := &goFacts{unused: map[string]map[string]bool{}}
	systems := systemsFor(runtime.GOOS)
	type step struct {
		mod string
		sys goSystem
	}
	// La machine d'abord pour chaque module, puis les systemes croises: un
	// delai qui tombe ne coute jamais l'analyse de la machine d'un module.
	var steps []step
	for _, sys := range systems {
		for _, m := range mods {
			steps = append(steps, step{m, sys})
		}
	}
	var runs []gvcRun
	var failed []string
	where := func(st step) string {
		if l := moduleLabel(st.mod); l != "" {
			return l + ", " + st.sys.label
		}
		return st.sys.label
	}
	for i, st := range steps {
		mdir := moduleDir(dir, st.mod)
		// -json rend un flux d'objets; -C fixe le dossier de travail sans
		// dependre du cwd du processus appelant. On vise tout le module.
		args := append(append([]string{}, g.pre...), "-json", "-C", mdir, "./...")
		res, err := runTool(st.sys.env(ctx), bin, mdir, args...)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && len(runs) > 0 {
				for _, rest := range steps[i:] {
					failed = append(failed, where(rest)+": interrompu, delai maximal atteint")
				}
				break
			}
			// Demarrage impossible, annulation, ou rien d'analyse a temps.
			return nil, nil, err
		}
		if nothingToBuild(res) {
			continue
		}
		// Seulement en compilation croisee: sur la machine, le meme message
		// peut venir d'un paquet cgo sans cgo, ce qui n'a rien de normal.
		if !st.sys.native && excludedBuild(res) {
			failed = append(failed, where(st)+": "+excludedBuildText)
			continue
		}
		run, err := interpretGovulncheckRun(res)
		if err != nil {
			failed = append(failed, where(st)+": "+err.Error())
			continue
		}
		run.system, run.module = st.sys.label, st.mod
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
	for _, m := range mods {
		if ctx.Err() != nil {
			break
		}
		if u := unusedModules(ctx, moduleDir(dir, m)); u != nil {
			facts.unused[manifestOf(m)] = u
		}
	}
	if capped {
		failed = append(failed, fmt.Sprintf("%d modules analyses au plus, les suivants non", MaxGoModules))
	}
	if more {
		failed = append(failed, "recherche des go.mod arretee, depot trop grand")
	}
	if len(runs) == 0 {
		fs := []finding.Finding{nothingToCheck("govulncheck",
			"aucun paquet Go a compiler pour Linux, macOS ni Windows",
			"Verifier que le depot contient du code Go hors des tests.")}
		if len(failed) > 0 {
			fs = append(fs, partialScan("govulncheck", failed))
		}
		return fs, facts, nil
	}
	fs := mergeRuns(runs)
	if len(failed) > 0 {
		fs = append(fs, partialScan("govulncheck", failed))
	}
	return fs, facts, nil
}

// handlesDeadline dit que govulncheck garde ce qui est fini quand le delai
// tombe.
func (Govulncheck) handlesDeadline() {}

// nothingToBuild reconnait govulncheck qui ne trouve aucun paquet a compiler
// pour ce systeme: tous les fichiers en sont exclus par leurs contraintes de
// build. Ce n'est pas une panne, ce systeme n'a simplement rien a analyser. Le
// message vient en dernier, apres d'eventuels telechargements de modules.
func nothingToBuild(res toolResult) bool {
	const msg = "no packages matched"
	return res.exitCode != 0 && (strings.Contains(res.stderr, msg) || strings.Contains(res.stderrTail, msg))
}

// excludedBuild reconnait un module dont un paquet importe un autre reserve a
// un autre systeme: un installeur Windows, par exemple, ne se compile pas pour
// Linux. Le message de Go est long et parle de nom de paquet invalide, le
// rapport dit plus simplement ce qui se passe.
func excludedBuild(res toolResult) bool {
	const msg = "build constraints exclude all Go files"
	return res.exitCode != 0 && (strings.Contains(res.stderr, msg) || strings.Contains(res.stderrTail, msg))
}

const excludedBuildText = "ne se compile pas pour ce systeme, du code y est reserve a un autre (contraintes de build). Normal pour un module propre a un systeme"

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
	Affected   []osvAffected  `json:"affected"`
}

// noFixFor dit que l'entree decrit le module mod et ne publie aucune version
// corrigee. Un module que l'entree ne decrit pas (remplace par un fork, par
// exemple) n'en dit rien: la version corrigee reste inconnue.
func (o gvcOSV) noFixFor(mod string) bool {
	known := false
	for _, a := range o.Affected {
		if a.Package.Name != mod {
			continue
		}
		for _, r := range a.Ranges {
			known = true
			for _, e := range r.Events {
				if e.Fixed != "" {
					return false
				}
			}
		}
	}
	return known
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
	// module est le dossier du module analyse, relatif au depot.
	module string
	osvs   map[string]gvcOSV
	best   map[gvcKey]gvcFinding
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
	run := gvcRun{osvs: map[string]gvcOSV{}, best: map[gvcKey]gvcFinding{}}
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
			id := gvcKey{msg.Finding.OSV, vulnModule(*msg.Finding)}
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

// gvcKey designe une vulnerabilite dans un module: une meme entree peut
// toucher x/net et stdlib, chacun a sa mise a jour.
type gvcKey struct{ osv, module string }

// vulnModule rend le module touche d'un constat, sans sa version.
func vulnModule(f gvcFinding) string {
	for _, fr := range f.Trace {
		if fr.Module != "" {
			return fr.Module
		}
	}
	return ""
}

// mergeRuns fusionne les executions par vulnerabilite et par module touche: la trace la plus
// specifique l'emporte, et le constat dit dans quels modules et sous quels
// systemes le code fautif est appele, module par module.
func mergeRuns(runs []gvcRun) []finding.Finding {
	osvByID := map[string]gvcOSV{}
	best := map[gvcKey]gvcFinding{}
	var mods []string                         // modules analyses, dans l'ordre
	analysed := map[string][]string{}         // module -> systemes analyses
	reach := map[gvcKey]map[string][]string{} // vulnerabilite -> module -> systemes
	foundIn := map[gvcKey][]string{}          // vulnerabilite -> modules ou elle est relevee
	for _, r := range runs {
		if !containsStr(mods, r.module) {
			mods = append(mods, r.module)
		}
		if r.system != "" && !containsStr(analysed[r.module], r.system) {
			analysed[r.module] = append(analysed[r.module], r.system)
		}
		for id, o := range r.osvs {
			osvByID[id] = o
		}
		for id, f := range r.best {
			prev, seen := best[id]
			if !seen || moreSpecific(f, prev) {
				best[id] = f
			}
			if !containsStr(foundIn[id], r.module) {
				foundIn[id] = append(foundIn[id], r.module)
			}
			if !f.reachable() {
				continue
			}
			if reach[id] == nil {
				reach[id] = map[string][]string{}
			}
			if !containsStr(reach[id][r.module], r.system) {
				reach[id][r.module] = append(reach[id][r.module], r.system)
			}
		}
	}

	ids := make([]gvcKey, 0, len(best))
	for id := range best {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].osv != ids[j].osv {
			return ids[i].osv < ids[j].osv
		}
		return ids[i].module < ids[j].module
	})

	var out []finding.Finding
	for _, id := range ids {
		var where []string
		for _, m := range mods {
			sys, ok := reach[id][m]
			if !ok {
				continue
			}
			var part []string
			// Le module ne se nomme que s'il y en a plusieurs, les systemes
			// que s'ils different de ceux analyses pour ce module.
			if len(mods) > 1 {
				part = append(part, "dans le "+orRoot(moduleLabel(m)))
			}
			if r := nonEmpty(sys); len(r) > 0 && len(r) < len(analysed[m]) {
				part = append(part, "sous "+joinFr(r))
			}
			if len(part) > 0 {
				where = append(where, strings.Join(part, " "))
			}
		}
		v := projectVuln(osvByID[id.osv], best[id], where)
		// Le go.mod de chaque module ou la faille est relevee: la commande de
		// mise a jour se lance dans son dossier (voir fixCommands).
		for _, m := range foundIn[id] {
			if m != "" {
				v.Evidence = append(v.Evidence, finding.Evidence{Type: "manifest", Data: manifestOf(m)})
			}
		}
		out = append(out, v)
	}
	return out
}

func nonEmpty(list []string) []string {
	var out []string
	for _, s := range list {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// moreSpecific prefere une trace atteignable, puis la plus longue.
func moreSpecific(a, b gvcFinding) bool {
	if a.reachable() != b.reachable() {
		return a.reachable()
	}
	return len(a.Trace) > len(b.Trace)
}

func projectVuln(osv gvcOSV, f gvcFinding, where []string) finding.Finding {
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
		Observed:    observedVuln(reach, f, where),
		Remediation: remediationVuln(f.FixedVersion, osv.noFixFor(vulnModule(f))),
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

	// Sans version corrigee, l'entree OSV dit s'il n'y en a pas de publiee.
	// Un module remplace par un fork n'y figure pas: rien n'est affirme.
	if f.FixedVersion != "" {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceFixedIn, Data: strings.TrimPrefix(f.FixedVersion, "v")})
	} else if osv.noFixFor(vulnModule(f)) {
		out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceNoFix, Data: "oui"})
	}
	out.Evidence = append(out.Evidence, finding.Evidence{Type: EvidenceEcosystem, Data: "Go"})

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

func observedVuln(reach bool, f gvcFinding, where []string) string {
	if reach {
		fr := f.Trace[0]
		loc := ""
		if fr.Position != nil {
			loc = fmt.Sprintf(" (%s:%d)", fr.Position.Filename, fr.Position.Line)
		}
		at := ""
		if len(where) > 0 {
			at = " " + strings.Join(where, ", ")
		}
		return fmt.Sprintf("symbole vulnerable atteignable%s: %s%s", at, fr.Function, loc)
	}
	return fmt.Sprintf("dependance vulnerable importee: %s", topModule(f))
}

func remediationVuln(fixed string, noFix bool) string {
	switch {
	case fixed != "":
		return "Mettre a jour la dependance vers " + fixed + " ou plus recent."
	case noFix:
		return "Aucune version corrigee publiee: isoler ou remplacer la dependance."
	}
	// Un module que l'entree ne decrit pas, souvent un fork mis a la place
	// par replace: sa version corrigee n'est pas connue.
	return "Version corrigee inconnue pour ce module, peut-etre remplace par un fork. Voir l'avis du module d'origine."
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
