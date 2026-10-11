// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

// TestHelperProcess n'est pas un test: c'est un faux moteur. runTool relance le
// binaire de test lui-meme avec QUAERO_TEST_HELPER=1, ce qui fonctionne a
// l'identique sous Windows, macOS et Linux, sans dependre d'un shell.
// Arguments apres "--": <code de sortie> <texte sur stdout> [dort].
func TestHelperProcess(t *testing.T) {
	if os.Getenv("QUAERO_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 3 {
		os.Exit(99)
	}
	code, _ := strconv.Atoi(args[1])
	if len(args) > 3 && args[3] == "dort" {
		time.Sleep(time.Minute)
	}
	fmt.Fprint(os.Stdout, args[2])
	os.Exit(code)
}

// helper lance le faux moteur avec le code et la sortie voulus.
func helper(t *testing.T, ctx context.Context, code int, stdout string, extra ...string) (toolResult, error) {
	t.Helper()
	t.Setenv("QUAERO_TEST_HELPER", "1")
	args := append([]string{"-test.run=^TestHelperProcess$", "--", strconv.Itoa(code), stdout}, extra...)
	return runTool(ctx, os.Args[0], t.TempDir(), args...)
}

func TestRunToolRendCodeEtSortie(t *testing.T) {
	res, err := helper(t, context.Background(), 1, `{"Issues":[]}`)
	if err != nil {
		t.Fatalf("runTool: %v", err)
	}
	if res.exitCode != 1 {
		t.Errorf("code = %d, attendu 1", res.exitCode)
	}
	if string(res.stdout) != `{"Issues":[]}` {
		t.Errorf("stdout = %q", res.stdout)
	}
}

func TestRunToolInterrompuAuDelai(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := helper(t, ctx, 0, "", "dort")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, attendu un depassement de delai", err)
	}
	// Le moteur dort une minute: s'il n'est pas tue, le test le verrait.
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("interruption trop lente: %s", d)
	}
}

func TestAcceptRefuseUnePanneDeguisee(t *testing.T) {
	cases := []struct {
		nom   string
		res   toolResult
		codes []int
		ok    bool
	}{
		{"zero sans sortie", toolResult{exitCode: 0}, []int{0}, true},
		{"un avec sortie", toolResult{exitCode: 1, stdout: []byte("{}")}, []int{0, 1}, true},
		{"un sans sortie", toolResult{exitCode: 1}, []int{0, 1}, false},
		{"code inattendu avec sortie", toolResult{exitCode: 2, stdout: []byte("{}")}, []int{0, 1}, false},
	}
	for _, c := range cases {
		err := c.res.accept(c.codes...)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, attendu ok=%v", c.nom, err, c.ok)
		}
	}
}

func TestFailureCiteLaSortieErreur(t *testing.T) {
	err := toolResult{name: "semgrep", exitCode: 2, stderr: "invalid config"}.failure()
	if !strings.Contains(err.Error(), "invalid config") || !strings.Contains(err.Error(), "2") {
		t.Errorf("message peu utile: %v", err)
	}
}

func TestInterpretOSVAucunManifeste(t *testing.T) {
	// 128: rien n'a ete verifie, ce qui ne doit pas passer pour un depot sain.
	fs, err := interpretOSV(toolResult{exitCode: 128})
	if err != nil {
		t.Fatalf("interpretOSV: %v", err)
	}
	if len(fs) != 1 || fs[0].ID != "QRO-SCAN-VIDE-osv-scanner" {
		t.Fatalf("attendu un constat 'rien a analyser', obtenu %+v", fs)
	}
}

func TestInterpretOSVErreurGenerale(t *testing.T) {
	if _, err := interpretOSV(toolResult{exitCode: 127, stderr: "boom"}); err == nil {
		t.Fatal("le code 127 est une panne")
	}
}

func TestInterpretGovulncheckCodeNonNul(t *testing.T) {
	// En mode -json, govulncheck sort en 0 meme avec des vulnerabilites: un
	// autre code est une panne, meme si un debut de flux a ete ecrit.
	res := toolResult{exitCode: 1, stdout: []byte(`{"config":{}}`)}
	if _, err := interpretGovulncheck(res); err == nil {
		t.Fatal("un code non nul de govulncheck -json est une panne")
	}
}

func TestInterpretGosecIssuesTrouvees(t *testing.T) {
	res := toolResult{exitCode: 1, stdout: []byte(`{"Issues":[{"severity":"HIGH","confidence":"HIGH","rule_id":"G401","details":"x","file":"a.go","line":"1","cwe":{"id":"327"}}]}`)}
	fs, err := interpretGosec(res)
	if err != nil {
		t.Fatalf("interpretGosec: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("constats = %d, attendu 1", len(fs))
	}
}

// funcScanner est un double dont le comportement est une fonction.
type funcScanner struct {
	name string
	scan func(ctx context.Context) ([]finding.Finding, error)
}

func (f funcScanner) Name() string    { return f.name }
func (f funcScanner) Available() bool { return true }
func (f funcScanner) Scan(ctx context.Context, _ string) ([]finding.Finding, error) {
	return f.scan(ctx)
}

func TestRunWithMoteurInterrompuNeParaitPasPropre(t *testing.T) {
	// Le moteur rend une liste vide sans erreur apres l'expiration: c'est
	// exactement le cas qui passait pour un depot sain.
	lent := funcScanner{name: "lent", scan: func(ctx context.Context) ([]finding.Finding, error) {
		<-ctx.Done()
		return nil, nil
	}}
	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{Timeout: 50 * time.Millisecond}, lent)
	if err != nil {
		t.Fatalf("RunWith: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "QRO-SCAN-ERREUR-lent" {
		t.Fatalf("attendu un constat d'erreur, obtenu %+v", rep.Findings)
	}
	if !strings.Contains(rep.Findings[0].Observed, "interrompu") {
		t.Errorf("observe = %q, attendu une interruption", rep.Findings[0].Observed)
	}
}

func TestRunWithMoteursEnParallele(t *testing.T) {
	// Rendez-vous: chaque moteur attend que l'autre ait demarre. En sequence,
	// le premier attendrait jusqu'a son delai et finirait en erreur.
	var started sync.WaitGroup
	started.Add(2)
	rdv := func(ctx context.Context) ([]finding.Finding, error) {
		started.Done()
		done := make(chan struct{})
		go func() { started.Wait(); close(done) }()
		select {
		case <-done:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a := funcScanner{name: "a", scan: rdv}
	b := funcScanner{name: "b", scan: rdv}

	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{Timeout: 5 * time.Second}, a, b)
	if err != nil {
		t.Fatalf("RunWith: %v", err)
	}
	for _, f := range rep.Findings {
		t.Errorf("constat inattendu %s: %s", f.ID, f.Observed)
	}
	d, ok := rep.Run.Context["durees_s"].(map[string]float64)
	if !ok || len(d) != 2 {
		t.Errorf("durees_s = %v, attendu une duree par moteur", rep.Run.Context["durees_s"])
	}
}

func TestRunWithGardeLOrdreDesMoteurs(t *testing.T) {
	// Le dernier lance finit le premier: le rapport reste dans l'ordre des
	// moteurs, pas dans l'ordre d'arrivee.
	mk := func(name string, wait time.Duration) funcScanner {
		return funcScanner{name: name, scan: func(context.Context) ([]finding.Finding, error) {
			time.Sleep(wait)
			return []finding.Finding{{ID: "F-" + name, Severity: finding.SeverityInfo, Status: finding.StatusReview}}, nil
		}}
	}
	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{}, mk("lent", 100*time.Millisecond), mk("vif", 0))
	if err != nil {
		t.Fatalf("RunWith: %v", err)
	}
	ran, _ := rep.Run.Context["scanners"].([]string)
	if len(ran) != 2 || ran[0] != "lent" || ran[1] != "vif" {
		t.Errorf("scanners = %v, attendu [lent vif]", ran)
	}
}

func TestInstallDirsInclutLocalBinPartout(t *testing.T) {
	// pipx et uv deposent leurs binaires dans ~/.local/bin, Windows compris.
	isolate(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	want := filepath.Join(home, ".local", "bin")
	for _, d := range installDirs() {
		if samePath(d, want) {
			return
		}
	}
	t.Errorf("%s absent de %v", want, installDirs())
}
