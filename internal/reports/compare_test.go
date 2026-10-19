// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package reports

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

func scanReport(when time.Time, engines []string, fs ...finding.Finding) *finding.Report {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{"cible": "github.com/acme/outil", "scanners": engines})
	for _, f := range fs {
		rep.Add(f)
	}
	rep.Run.StartedAt, rep.Run.FinishedAt = when, when
	return rep
}

func codeF(id, title, loc, line, engine string) finding.Finding {
	return finding.Finding{ID: id, Title: title, Severity: finding.SeverityMedium, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "code", Identifier: loc},
		Evidence: []finding.Evidence{{Type: "code", Data: line}, {Type: "engine", Data: engine}}}
}

func depF(id, module string, refs ...string) finding.Finding {
	f := finding.Finding{ID: id, Title: "faille " + id, Severity: finding.SeverityHigh, Status: finding.StatusReview,
		Target: &finding.Target{Type: "dependency", Identifier: module}, Evidence: []finding.Evidence{{Type: "engine", Data: "osv-scanner"}}}
	for _, r := range refs {
		f.References = append(f.References, finding.Reference{Framework: "OSV", ID: r})
	}
	return f
}

// Un constat deplace reste le meme, un constat disparu est corrige, un
// constat apparu est nouveau. Un moteur qui n'a pas tourne dans les deux
// analyses n'affirme rien.
func TestComparaison(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	prev := scanReport(t0, []string{"gosec", "osv-scanner"},
		codeF("A", "G204: Subprocess", "a.go:3", "exec.Command(x)", "gosec"),
		codeF("B", "G304: File inclusion", "b.go:5", "os.ReadFile(p)", "gosec"),
		depF("D1", "golang.org/x/net@0.35.0", "GO-1"),
		depF("D2", "stdlib@1.25", "GO-2"),
		// Une ancienne version fusionnait x/net et stdlib sous un seul constat.
		depF("D9", "golang.org/x/text@0.20.0", "GO-9"),
	)
	prev.Run.Context["commit"] = "1e21e54a1375d5badd8c62fcd77d4dbc505a209d"
	cur := scanReport(t0.Add(time.Hour), []string{"gosec", "osv-scanner", "semgrep"},
		codeF("A2", "G204: Subprocess", "a.go:10", "exec.Command(x)", "gosec"),
		codeF("C", "G101: Secret", "c.go:1", `token := "abc"`, "gosec"),
		codeF("S", "regle: motif", "d.go:2", "x()", "semgrep"),
		depF("D2b", "stdlib@1.25", "GO-2"),
		depF("D3", "golang.org/x/text@0.20.0", "GO-3"),
		depF("D9a", "golang.org/x/text@0.20.0", "GO-9"),
		depF("D9b", "stdlib@1.25", "GO-9"),
	)
	cur.Run.Context["format_constats"] = 2
	d := Compare("r1", prev, cur)
	sort.Strings(d.New)
	if !reflect.DeepEqual(d.New, []string{"C", "D3"}) {
		t.Errorf("nouveaux %v", d.New)
	}
	var fixed []string
	for _, g := range d.Fixed {
		fixed = append(fixed, g.ID)
	}
	sort.Strings(fixed)
	if !reflect.DeepEqual(fixed, []string{"B", "D1"}) {
		t.Errorf("corriges %v", fixed)
	}
	if d.Unchanged != 4 || d.Uncompared != 1 || !reflect.DeepEqual(d.Engines, []string{"semgrep"}) {
		t.Errorf("inchanges %d, non compares %d %v", d.Unchanged, d.Uncompared, d.Engines)
	}
	if d.Previous != "r1" || !d.Since.Equal(t0) || d.Commit == "" {
		t.Errorf("precedente %+v", d)
	}
	if s := DiffSummary(d); s != "Analyse du "+t0.Local().Format("02/01/2006 à 15h04")+", commit `1e21e54`. 2 corrigés, 2 nouveaux. Rapport d'une version antérieure de Quaero, qui rangeait autrement les constats, quelques-uns peuvent être comptés à tort. 1 constat non comparé, semgrep n'a pas tourné entièrement dans les deux analyses." {
		t.Errorf("resume %q", s)
	}
}

// Un moteur en echec, ou sans rien a lire, dans l'analyse du jour ne corrige
// rien. Un constat releve par deux moteurs n'est corrige que si les deux ont
// tourne: celui qui manque l'aurait peut-etre releve.
func TestMoteurEnEchecNeCorrigeRien(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for _, meta := range []string{"QRO-SCAN-ERREUR-gosec", "QRO-SCAN-VIDE-gosec", "QRO-SCAN-PARTIEL-gosec", "QRO-SCAN-ABSENT-gosec"} {
		prev := scanReport(t0, []string{"gosec"}, codeF("B", "G304: File inclusion", "b.go:5", "os.ReadFile(p)", "gosec"))
		cur := scanReport(t0.Add(time.Hour), []string{"gosec"})
		cur.Add(finding.Finding{ID: meta, Title: "x", Severity: finding.SeverityInfo, Status: finding.StatusReview})
		if d := Compare("r1", prev, cur); len(d.Fixed) != 0 || d.Uncompared != 1 {
			t.Errorf("%s: %+v", meta, d)
		}
	}
	merged := codeF("M", "dangerous-exec-command: x", "a.go:3", "exec.Command(x)", "semgrep")
	merged.Evidence = append(merged.Evidence, finding.Evidence{Type: "engine", Data: "gosec"})
	prev := scanReport(t0, []string{"semgrep", "gosec"}, merged)
	cur := scanReport(t0.Add(time.Hour), []string{"semgrep", "gosec"})
	cur.Add(finding.Finding{ID: "QRO-SCAN-ABSENT-gosec", Title: "x", Severity: finding.SeverityInfo, Status: finding.StatusReview})
	if d := Compare("r1", prev, cur); len(d.Fixed) != 0 || d.Uncompared != 1 {
		t.Errorf("fusionne: %+v", d)
	}
}

// Les correspondances larges s'apparient un a un: une seconde ligne
// identique est nouvelle, une regle nouvelle sur une ligne deja relevee
// aussi, et un paquet qui prend une CVE deja portee par un autre aussi.
func TestNouveauteMalgreUneLigneSemblable(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	prev := scanReport(t0, []string{"gosec", "semgrep", "osv-scanner"},
		codeF("A", "G204: Subprocess", "a.go:3", "exec.Command(x)", "gosec"),
		codeF("E", "G104: Errors unhandled", "e.go:7", "f.Close()", "gosec"),
		depF("N1", "golang.org/x/net@0.10.0", "CVE-2023-44487"),
	)
	prev.Run.Context["format_constats"] = 2
	cur := scanReport(t0.Add(time.Hour), []string{"gosec", "semgrep", "osv-scanner"},
		codeF("A1", "G204: Subprocess", "a.go:3", "exec.Command(x)", "gosec"),
		codeF("A2", "G204: Subprocess", "a.go:40", "exec.Command(x)", "gosec"),
		codeF("E1", "G104: Errors unhandled", "e.go:7", "f.Close()", "gosec"),
		codeF("S1", "close-error: motif", "e.go:7", "f.Close()", "semgrep"),
		depF("N2", "golang.org/x/net@0.10.0", "CVE-2023-44487"),
		depF("N3", "io.netty:netty-codec-http2@4.1.99.Final", "CVE-2023-44487"),
	)
	cur.Run.Context["format_constats"] = 2
	d := Compare("r1", prev, cur)
	sort.Strings(d.New)
	if !reflect.DeepEqual(d.New, []string{"A2", "N3", "S1"}) || d.Unchanged != 3 || len(d.Fixed) != 0 {
		t.Errorf("nouveaux %v, inchanges %d, corriges %v", d.New, d.Unchanged, d.Fixed)
	}
}

// Une ligne dont le titre ou le moteur retenu change d'une version a l'autre
// reste la meme, tant qu'une regle est commune.
func TestMemeLigneAutreTitre(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	old := codeF("A", "dangerous-exec-command: ancien message", "a.go:3", "exec.Command(x)", "semgrep")
	old.Evidence = append(old.Evidence, finding.Evidence{Type: "rule", Data: "go.r.dangerous-exec-command"}, finding.Evidence{Type: "fusionne", Data: "G204: Subprocess (gosec)"})
	now := codeF("B", "G204: Subprocess launched with variable", "a.go:9", "exec.Command(x)", "gosec")
	now.Evidence = append(now.Evidence, finding.Evidence{Type: "rule", Data: "go.r.dangerous-exec-command"})
	prev := scanReport(t0, []string{"gosec", "semgrep"}, old)
	cur := scanReport(t0.Add(time.Hour), []string{"gosec", "semgrep"}, now)
	if d := Compare("r1", prev, cur); len(d.New) != 0 || len(d.Fixed) != 0 || d.Unchanged != 1 {
		t.Errorf("%+v", d)
	}
}

// L'analyse precedente est la plus recente du meme depot avant celle-ci, sans
// jamais etre elle-meme.
func TestAnalysePrecedente(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	save := func(rep *finding.Report) string {
		e, err := s.Save(rep)
		if err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	first := save(scanReport(t0, []string{"gosec"}))
	other := scanReport(t0.Add(time.Hour), []string{"gosec"})
	other.Run.Context["cible"] = "github.com/autre/depot"
	save(other)
	second := save(scanReport(t0.Add(2*time.Hour), []string{"gosec"}))

	cur := scanReport(t0.Add(3*time.Hour), []string{"gosec"})
	if id, _ := s.Previous(cur); id != second {
		t.Errorf("precedente %q, attendu %q", id, second)
	}
	reopened, err := s.Load(second)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := s.Previous(reopened); id != first {
		t.Errorf("precedente du rapport rouvert %q, attendu %q", id, first)
	}
	if d := s.DiffWith(scanReport(t0.Add(-time.Hour), []string{"gosec"})); d == nil || d.Previous != "" {
		t.Errorf("rien avant: %+v", d)
	}

	// Un dossier local ne se compare qu'aux rapports de la meme machine.
	local := func(when time.Time, host string) *finding.Report {
		rep := scanReport(when, []string{"gosec"})
		rep.Run.Context["cible"], rep.Run.Host = "/home/moi/projet", host
		return rep
	}
	mine := save(local(t0, "ici"))
	save(local(t0.Add(time.Hour), "ailleurs"))
	if id, _ := s.Previous(local(t0.Add(2*time.Hour), "ICI")); id != mine {
		t.Errorf("dossier local: %q, attendu %q", id, mine)
	}
	// Avec l'identifiant de la machine, le nom ne compte plus: il change avec
	// le reseau.
	posted := func(when time.Time, host, poste string) *finding.Report {
		rep := local(when, host)
		rep.Run.Context["poste"] = poste
		return rep
	}
	here := save(posted(t0.Add(3*time.Hour), "bureau.local", "aaaa"))
	save(posted(t0.Add(4*time.Hour), "maison.local", "bbbb"))
	if id, _ := s.Previous(posted(t0.Add(5*time.Hour), "maison.local", "aaaa")); id != here {
		t.Errorf("meme poste, autre nom: %q, attendu %q", id, here)
	}
}

// govulncheck reste souvent en partie, sur un outil qui ne se compile pas pour
// tous les systemes: une dependance que lit aussi osv-scanner, entierement, se
// dit corrigee quand meme. Un constat que seul un moteur en partie relevait
// reste non compare.
func TestCorrigeMalgreUnMoteurEnPartie(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	both := depF("N", "golang.org/x/net@0.10.0", "GO-1")
	both.Evidence = append(both.Evidence, finding.Evidence{Type: "engine", Data: "govulncheck"})
	only := codeF("G", "G304: File inclusion", "b.go:5", "os.ReadFile(p)", "gosec")
	partialRep := func(when time.Time, fs ...finding.Finding) *finding.Report {
		rep := scanReport(when, []string{"osv-scanner", "govulncheck", "gosec"}, fs...)
		for _, e := range []string{"govulncheck", "gosec"} {
			rep.Add(finding.Finding{ID: "QRO-SCAN-PARTIEL-" + e, Title: "x", Severity: finding.SeverityInfo, Status: finding.StatusReview})
		}
		return rep
	}
	d := Compare("r1", partialRep(t0, both, only), partialRep(t0.Add(time.Hour)))
	if len(d.Fixed) != 1 || d.Fixed[0].ID != "N" || d.Uncompared != 1 {
		t.Errorf("%+v", d)
	}
}

// Des milliers de constats sans empreinte commune, apres un dossier renomme,
// se comparent vite.
func TestComparaisonRapide(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	var old, now []finding.Finding
	for i := range 5000 {
		snippet := fmt.Sprintf("%d: x := f()\n%d: _ = g(%d)\n%d: h()", i, i+1, i, i+2)
		old = append(old, codeF(fmt.Sprintf("O%d", i), "G104: Errors unhandled", fmt.Sprintf("ancien/f.go:%d", i+1), snippet, "gosec"))
		now = append(now, codeF(fmt.Sprintf("N%d", i), "G104: Errors unhandled", fmt.Sprintf("nouveau/f.go:%d", i+1), snippet, "gosec"))
	}
	start := time.Now()
	d := Compare("r1", scanReport(t0, []string{"gosec"}, old...), scanReport(t0.Add(time.Hour), []string{"gosec"}, now...))
	if took := time.Since(start); took > 5*time.Second || len(d.New) != 5000 || len(d.Fixed) != 5000 {
		t.Errorf("%v, %d nouveaux, %d corriges", took, len(d.New), len(d.Fixed))
	}
}
