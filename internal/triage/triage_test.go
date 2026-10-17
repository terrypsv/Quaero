// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package triage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

func gosecAt(line int, snippet string) finding.Finding {
	return finding.Finding{
		ID:       "QRO-GOSEC-G304-internal-a-go-" + itoa(line),
		Title:    "G304: Potential file inclusion via variable",
		Severity: finding.SeverityMedium, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "code", Identifier: "internal/a.go:" + itoa(line)},
		Evidence: []finding.Evidence{{Type: "code", Data: snippet}},
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// fp rend l'empreinte d'un constat seul dans son rapport.
func fp(f finding.Finding) string { return Fingerprints(report("github.com/a/b", f))[f.ID] }

func report(cible string, fs ...finding.Finding) *finding.Report {
	rep := finding.NewReport(finding.Tool{Name: "quaero"}, "h", map[string]any{"cible": cible})
	for _, f := range fs {
		rep.Add(f)
	}
	return rep
}

// Une ligne ajoutee plus haut deplace le constat sans changer son empreinte.
// Un changement de la ligne elle-meme la change. Les voisines n'y sont pas.
func TestEmpreinteStable(t *testing.T) {
	a := gosecAt(147, "146: func f(p string) {\n147: \tf, err := os.OpenFile(p, os.O_RDONLY, 0)\n148: \tif err != nil {")
	moved := gosecAt(152, "151: // une ligne de plus au-dessus\n152: \tf, err := os.OpenFile(p, os.O_RDONLY, 0)\n153: \tif err != nil {")
	changed := gosecAt(147, "146: func f(p string) {\n147: \tf, err := os.OpenFile(clean(p), os.O_RDONLY, 0)\n148: \tif err != nil {")
	if fp(a) != fp(moved) {
		t.Error("une ligne ajoutee plus haut change l'empreinte")
	}
	if fp(a) == fp(changed) {
		t.Error("la ligne a change, l'empreinte non")
	}
	sem := finding.Finding{ID: "QRO-SEMGREP-x-a-go-3", Title: "x: y", Target: &finding.Target{Type: "code", Identifier: "a.go:3"},
		Evidence: []finding.Evidence{{Type: "code", Data: "  exec.Command(name,   args...)  "}, {Type: "rule", Data: "go.lang.x"}}}
	sem2 := sem
	sem2.Target = &finding.Target{Type: "code", Identifier: "a.go:9"}
	sem2.Evidence = []finding.Evidence{{Type: "code", Data: "exec.Command(name, args...)"}, {Type: "rule", Data: "go.lang.x"}}
	if fp(sem) != fp(sem2) {
		t.Error("semgrep: les espaces ou la ligne changent l'empreinte")
	}
	// Une vulnerabilite publiee tient au paquet et a son identifiant, pas a
	// la version ni au moteur.
	osv := finding.Finding{ID: "QRO-OSV-GO-1-x", Target: &finding.Target{Type: "dependency", Identifier: "golang.org/x/net@0.35.0"},
		References: []finding.Reference{{Framework: "OSV", ID: "GO-1"}}}
	gvc := finding.Finding{ID: "QRO-VULN-GO-1", Target: &finding.Target{Type: "code", Identifier: "golang.org/x/net@v0.36.0"},
		References: []finding.Reference{{Framework: "OSV", ID: "GO-1"}, {Framework: "CVE", ID: "CVE-1"}}}
	if fp(osv) != fp(gvc) {
		t.Error("meme vulnerabilite, empreintes differentes")
	}
}

// Une decision survit a l'analyse suivante du meme depot, pas a celle d'un
// autre depot. Remettre a verifier l'efface.
func TestDecisionGardee(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".quaero", "tri.json")
	s := &Store{Path: path}
	first := report("github.com/A/B", gosecAt(147, "147: \tos.OpenFile(p)"))
	d, err := s.Set(first, first.Findings[0].ID, FalsePositive, "  chemin  fixe\nsous root ")
	if err != nil || d.State != FalsePositive || d.Note != "chemin fixe sous root" {
		t.Fatalf("Set: %+v %v", d, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("droits: %v %v", info.Mode().Perm(), err)
		}
	}
	// Relu par un autre processus, sur l'analyse suivante ou la ligne a bouge.
	next := report("github.com/a/b", gosecAt(160, "160: \tos.OpenFile(p)"))
	got := (&Store{Path: path}).For(next)
	if got[next.Findings[0].ID].State != FalsePositive {
		t.Errorf("decision perdue: %+v", got)
	}
	if other := (&Store{Path: path}).For(report("github.com/a/c", gosecAt(147, "147: \tos.OpenFile(p)"))); len(other) != 0 {
		t.Errorf("decision appliquee a un autre depot: %+v", other)
	}
	if _, err := s.Set(next, next.Findings[0].ID, ToReview, ""); err != nil {
		t.Fatal(err)
	}
	if got := (&Store{Path: path}).For(next); len(got) != 0 {
		t.Errorf("decision non effacee: %+v", got)
	}
	var raw struct{ Cibles map[string]any }
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &raw)
	if len(raw.Cibles) != 0 {
		t.Errorf("cible vide gardee: %s", data)
	}
}

func TestRefus(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "tri.json")}
	rep := report("github.com/a/b", gosecAt(1, "1: x"))
	if _, err := s.Set(rep, "absent", Confirmed, ""); !errors.Is(err, ErrUnknownFinding) {
		t.Errorf("constat absent: %v", err)
	}
	meta := report("github.com/a/b", finding.Finding{ID: "QRO-SCAN-ABSENT-gosec"})
	if _, err := s.Set(meta, "QRO-SCAN-ABSENT-gosec", Confirmed, ""); !errors.Is(err, ErrUnknownFinding) {
		t.Errorf("constat d'analyse: %v", err)
	}
	if _, err := s.Set(report("", gosecAt(1, "1: x")), gosecAt(1, "").ID, Confirmed, ""); !errors.Is(err, ErrNoTarget) {
		t.Errorf("sans cible: %v", err)
	}
	if _, ok := ParseState("supprime"); ok {
		t.Error("etat inconnu accepte")
	}
	long := strings.Repeat("é", MaxNote+20)
	d, _ := s.Set(rep, rep.Findings[0].ID, Confirmed, long)
	if n := len([]rune(d.Note)); n != MaxNote {
		t.Errorf("note de %d caracteres", n)
	}
}

// Un fichier abime n'est ni ecrase ni pris pour vide.
func TestFichierAbime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tri.json")
	_ = os.WriteFile(path, []byte("{pas du json"), 0o600)
	s := &Store{Path: path}
	rep := report("github.com/a/b", gosecAt(1, "1: x"))
	if _, err := s.Set(rep, rep.Findings[0].ID, Confirmed, ""); err == nil || !strings.Contains(err.Error(), "illisible") {
		t.Errorf("Set sur un fichier abime: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "{pas du json" {
		t.Error("fichier abime ecrase")
	}
}

func TestCleLocaleSousWindows(t *testing.T) {
	a := TargetKey(report(`C:\Users\Moi\Projet`))
	b := TargetKey(report(`c:\users\moi\projet\`))
	if runtime.GOOS == "windows" && a != b {
		t.Errorf("casse ou separateur final: %q %q", a, b)
	}
	if TargetKey(report("GitHub.com/Owner/Repo")) != "github.com/owner/repo" {
		t.Error("cible GitHub non normalisee")
	}
}

// Deux lignes identiques du meme fichier ne partagent pas une decision. La
// plage de gosec et le texte retenu par semgrep ne brouillent pas l'empreinte.
func TestEmpreintesDistinctes(t *testing.T) {
	a := gosecAt(10, "10: \tcmd := exec.Command(name, args...)")
	b := gosecAt(40, "40: \tcmd := exec.Command(name, args...)")
	fps := Fingerprints(report("github.com/a/b", a, b))
	if fps[a.ID] == fps[b.ID] || fps[a.ID] == "" {
		t.Fatalf("deux lignes identiques, une empreinte: %v", fps)
	}
	s := &Store{Path: filepath.Join(t.TempDir(), "tri.json")}
	rep := report("github.com/a/b", a, b)
	if _, err := s.Set(rep, a.ID, FalsePositive, ""); err != nil {
		t.Fatal(err)
	}
	if got := s.For(rep); len(got) != 1 || got[a.ID].State != FalsePositive {
		t.Errorf("la decision deborde: %+v", got)
	}

	ranged := gosecAt(0, "11: x\n12: \tos.Remove(p)\n13: y")
	ranged.Target.Identifier = "internal/a.go:12-14"
	moved := gosecAt(0, "21: z\n22: \tos.Remove(p)\n23: w")
	moved.Target.Identifier = "internal/a.go:22-24"
	if fp(ranged) != fp(moved) {
		t.Error("plage gosec: les voisines changent l'empreinte")
	}

	login := func(line int) finding.Finding {
		return finding.Finding{ID: "QRO-SEMGREP-r-a-go-" + itoa(line), Title: "r: m",
			Target:   &finding.Target{Type: "code", Identifier: "a.go:" + itoa(line)},
			Evidence: []finding.Evidence{{Type: "code", Data: "requires login"}, {Type: "rule", Data: "go.r"}}}
	}
	l1, l2 := login(3), login(9)
	if fps := Fingerprints(report("github.com/a/b", l1, l2)); fps[l1.ID] == fps[l2.ID] {
		t.Error("« requires login » confond deux constats")
	}
}

// Une ecriture ratee ne laisse pas la decision en memoire.
func TestEcritureRatee(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "fichier")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	s := &Store{Path: filepath.Join(blocker, "tri.json")}
	rep := report("github.com/a/b", gosecAt(1, "1: x"))
	if _, err := s.Set(rep, rep.Findings[0].ID, Confirmed, ""); err == nil {
		t.Fatal("ecriture impossible acceptee")
	}
	if got := s.For(rep); len(got) != 0 {
		t.Errorf("decision gardee sans ecriture: %+v", got)
	}
}

// Deux Quaero sur le meme fichier ne s'effacent pas.
func TestDeuxInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tri.json")
	a, b := &Store{Path: path}, &Store{Path: path}
	rep := report("github.com/a/b", gosecAt(1, "1: x"), gosecAt(2, "2: y"))
	if _, err := a.Set(rep, rep.Findings[0].ID, Confirmed, ""); err != nil {
		t.Fatal(err)
	}
	_ = b.For(rep)
	time.Sleep(20 * time.Millisecond)
	if _, err := b.Set(rep, rep.Findings[1].ID, FalsePositive, ""); err != nil {
		t.Fatal(err)
	}
	got := (&Store{Path: path}).For(rep)
	if got[rep.Findings[0].ID].State != Confirmed || got[rep.Findings[1].ID].State != FalsePositive {
		t.Errorf("une decision perdue: %+v", got)
	}
}

// Le fichier n'est jamais ecrit plus gros que ce qui se relit, et « < » ne
// compte que pour un octet.
func TestTailleBornee(t *testing.T) {
	old := maxFileBytes
	maxFileBytes = 1024
	defer func() { maxFileBytes = old }()
	path := filepath.Join(t.TempDir(), "tri.json")
	s := &Store{Path: path}
	rep := report("github.com/a/b", gosecAt(1, "1: x"), gosecAt(2, "2: y"))
	note := strings.Repeat("<", MaxNote)
	if _, err := s.Set(rep, rep.Findings[0].ID, Confirmed, note); err != nil {
		t.Fatalf("premiere decision: %v", err)
	}
	if _, err := s.Set(rep, rep.Findings[1].ID, Confirmed, note); !errors.Is(err, ErrTooBig) {
		t.Errorf("fichier trop gros accepte: %v", err)
	}
	got := (&Store{Path: path}).For(rep)
	if len(got) != 1 || got[rep.Findings[0].ID].Note != note {
		t.Errorf("relecture: %+v", got)
	}
}
