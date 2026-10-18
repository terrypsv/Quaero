// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package reports

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

func sample(cible string) *finding.Report {
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{"cible": cible, "commit": strings.Repeat("b", 40)})
	rep.Add(finding.Finding{ID: "QRO-SEMGREP-x-a-go-1", Title: "x", Severity: finding.SeverityHigh, Status: finding.StatusReview})
	rep.Add(finding.Finding{ID: "QRO-SCAN-ABSENT-gosec", Title: "absent", Severity: finding.SeverityInfo, Status: finding.StatusReview})
	rep.Finish()
	return rep
}

func TestEnregistrerRelireEffacer(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "rapports")}
	e, err := s.Save(sample("github.com/a/b"))
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(e.ID) || e.Target != "github.com/a/b" || e.Findings != 1 || e.Commit == "" {
		t.Errorf("resume %+v", e)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(s.Dir, e.ID+".json")); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("droits du rapport: %v %v", info.Mode().Perm(), err)
		}
	}
	rep, err := s.Load(e.ID)
	if err != nil || len(rep.Findings) != 2 {
		t.Fatalf("relecture: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	e2, _ := s.Save(sample("/home/moi/projet"))
	list, err := s.List()
	if err != nil || len(list) != 2 || list[0].ID != e2.ID {
		t.Errorf("liste %+v, %v", list, err)
	}
	if err := s.Delete(e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("rapport efface encore lisible: %v", err)
	}
}

// Seuls les noms tires par Quaero touchent au disque.
func TestNomsRefuses(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, id := range []string{"", "../config", "..", "a/b", `a\b`, "20261012-153200-abcdef01234", "20261012-153200-abcdef012345.json", "x",
		"Argus_2026-10-18_18-26-57_abcdef", "argus_2026-10-18_18-26-57_abcde", "-argus_2026-10-18_18-26-57_abcdef",
		"../argus_2026-10-18_18-26-57_abcdef", "argus_2026-10-18_18h26_abcdef", "argus-_2026-10-18_18-26-57_abcdef"} {
		if ValidID(id) {
			t.Errorf("%q accepte", id)
		}
		if _, err := s.Load(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Load(%q): %v", id, err)
		}
		if err := s.Delete(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q): %v", id, err)
		}
	}
}

func TestImport(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	data, _ := json.Marshal(sample("github.com/a/b"))
	e, _, err := s.Import(data)
	if err != nil || e.Target != "github.com/a/b" {
		t.Fatalf("import: %+v %v", e, err)
	}
	for name, bad := range map[string]string{
		"pas du json":       "bonjour",
		"autre schema":      `{"schema_version":"2.0","tool":{"name":"x"},"findings":[]}`,
		"sans outil":        `{"schema_version":"1.0","tool":{"name":""},"findings":[]}`,
		"sans constats":     `{"schema_version":"1.0","tool":{"name":"x"}}`,
		"tableau a la base": `[]`,
	} {
		if _, _, err := s.Import([]byte(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, attendu un refus", name, err)
		}
	}
}

// Le nom du fichier ne vient jamais du rapport importe.
func TestImportNomTire(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	rep := sample("x")
	rep.Run.ID = "../../evade"
	data, _ := json.Marshal(rep)
	e, _, err := s.Import(data)
	if err != nil || !ValidID(e.ID) || strings.Contains(e.ID, "evade") {
		t.Errorf("import: %+v %v", e, err)
	}
	files, _ := os.ReadDir(s.Dir)
	if len(files) != 1 {
		t.Errorf("%d fichiers ecrits", len(files))
	}
}

func TestListeDossierAbsent(t *testing.T) {
	list, err := (&Store{Dir: filepath.Join(t.TempDir(), "absent")}).List()
	if err != nil || len(list) != 0 {
		t.Errorf("liste %v, %v", list, err)
	}
}

// La liste compte comme la page: une dependance avec plusieurs vulnerabilites
// publiees ne compte qu'une fois.
func TestCompteCommeLaPage(t *testing.T) {
	dep := func(id, ident string) finding.Finding {
		return finding.Finding{ID: id, Title: id, Severity: finding.SeverityHigh, Status: finding.StatusReview,
			Target: &finding.Target{Type: "dependency", Identifier: ident}}
	}
	list := []finding.Finding{
		{ID: "QRO-SEMGREP-x-a-go-1", Title: "x", Severity: finding.SeverityHigh, Status: finding.StatusReview},
		dep("GHSA-1", "golang.org/x/net@0.35.0"),
		dep("GHSA-2", "golang.org/x/net@0.36.0"),
		dep("GHSA-3", "golang.org/x/crypto@0.33.0"),
		{ID: "QRO-VULN-GO-1", Title: "y", Severity: finding.SeverityHigh, Status: finding.StatusReview,
			Target:     &finding.Target{Type: "code", Identifier: "golang.org/x/net@v0.35.0"},
			References: []finding.Reference{{Framework: "OSV", ID: "GO-1"}}},
	}
	// Le symbole atteignable de x/net rejoint le paquet x/net, comme dans la page.
	if n := shownCount(list); n != 3 {
		t.Errorf("compte %d, attendu 3 (un constat de code, deux paquets)", n)
	}
}

// Un rapport exporte puis reimporte n'est pas range deux fois.
func TestImportSansDoublon(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	saved, err := s.Save(sample("github.com/a/b"))
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := s.Load(saved.ID)
	data, _ := json.Marshal(rep)
	again, existing, err := s.Import(data)
	if err != nil || again.ID != saved.ID || !existing {
		t.Errorf("reimport: %+v %v %v, attendu %s deja range", again, existing, err, saved.ID)
	}
	other := sample("github.com/a/b")
	other.Run.FinishedAt = rep.Run.FinishedAt
	data, _ = json.Marshal(other)
	if e, existing, err := s.Import(data); err != nil || e.ID == saved.ID || existing {
		t.Errorf("une autre analyse de la meme seconde doit etre rangee a part: %+v %v", e, err)
	}
	files, _ := os.ReadDir(s.Dir)
	if len(files) != 2 {
		t.Errorf("%d fichiers, attendu 2", len(files))
	}
}

// Un rapport que Load ne saurait pas relire n'est pas ecrit.
func TestTropGrosPasEcrit(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	rep := sample("x")
	for i := 0; i < maxFindings; i++ {
		rep.Findings = append(rep.Findings, finding.Finding{ID: "f", Title: "t"})
	}
	if _, err := s.Save(rep); !errors.Is(err, ErrTooBig) {
		t.Errorf("Save: %v, attendu ErrTooBig", err)
	}
	files, _ := os.ReadDir(s.Dir)
	if len(files) != 0 {
		t.Errorf("%d fichiers ecrits", len(files))
	}
}

// Un contexte demesure est refuse avant le decodage complet.
func TestContexteBorne(t *testing.T) {
	big := `{"schema_version":"1.0","tool":{"name":"x"},"findings":[],"run":{"context":{"k":[` + strings.Repeat("[],", maxContextBytes/3) + `[]]}}}`
	if _, err := Parse([]byte(big)); !errors.Is(err, ErrInvalid) {
		t.Errorf("contexte enorme: %v, attendu un refus", err)
	}
}

// La date d'un rapport importe ne choisit pas son nom, et une date future ne le
// garde pas en tete: il ne passe pas devant une analyse rangee apres lui.
func TestImportDateLibre(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	futur := sample("futur")
	futur.Run.FinishedAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("x", -(23*3600+59*60)))
	data, _ := json.Marshal(futur)
	e, _, err := s.Import(data)
	if err != nil || !ValidID(e.ID) {
		t.Fatalf("import: %+v %v", e, err)
	}
	if _, err := s.Load(e.ID); err != nil {
		t.Errorf("rapport importe illisible: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	recent, _ := s.Save(sample("recent"))
	list, _ := s.List()
	if len(list) != 2 || list[0].ID != recent.ID {
		t.Errorf("le dernier range doit venir en tete: %+v", list)
	}
}

// La liste suit la date des analyses: un vieux rapport importe apres coup se
// range a sa date, sous les analyses plus recentes.
func TestListeParDateDAnalyse(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	recent, _ := s.Save(sample("recent"))
	vieux := sample("vieux")
	vieux.Run.StartedAt = time.Date(2025, 3, 1, 10, 0, 0, 0, time.UTC)
	vieux.Run.FinishedAt = vieux.Run.StartedAt.Add(time.Minute)
	data, _ := json.Marshal(vieux)
	time.Sleep(1100 * time.Millisecond)
	if _, _, err := s.Import(data); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List()
	if len(list) != 2 || list[0].ID != recent.ID || list[1].Target != "vieux" {
		t.Errorf("ordre %+v", list)
	}
}

func TestSuppressionAbsente(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if err := s.Delete("20261012-153200-abcdef012345"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete d'un absent: %v", err)
	}
}

// Le nom dit la cible et la date, et le fichier se lit dans un editeur.
func TestNomLisible(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	e, err := s.Save(sample(`C:\Users\Terry PASSAVE\Desktop\Argus`))
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(e.ID) || !strings.HasPrefix(e.ID, "argus_"+time.Now().Format("2006-01-02")) {
		t.Errorf("nom %q", e.ID)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, e.ID+".json"))
	if err != nil || !strings.Contains(string(data), "\n  \"run\": {") {
		t.Errorf("rapport non indente: %v %.80s", err, data)
	}
	for target, want := range map[string]string{
		"github.com/Owner/Repo.go":     "owner-repo-go",
		"/home/moi/Projet Été/":        "projet-ete",
		`C:\Users\Terry PASSAVE\Argus`: "argus",
		"":                             "rapport",
		"../..":                        "rapport",
		strings.Repeat("a", 60):        strings.Repeat("a", 40),
		"x---y":                        "x-y",
	} {
		if got := Slug(target); got != want {
			t.Errorf("Slug(%q) = %q, attendu %q", target, got, want)
		}
	}
}

// Les rapports ranges sous l'ancien nom restent dans la liste.
func TestAncienNomRelu(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	data, _ := json.Marshal(sample("ancien"))
	const old = "20261012-153200-abcdef012345"
	if err := os.WriteFile(filepath.Join(s.Dir, old+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	recent, err := s.Save(sample("recent"))
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil || len(list) != 2 || list[0].ID != recent.ID || list[1].ID != old {
		t.Fatalf("liste %+v %v", list, err)
	}
	if err := s.Delete(old); err != nil {
		t.Errorf("ancien nom non efface: %v", err)
	}
}
