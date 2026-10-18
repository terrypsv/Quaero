// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

// TestGvcHelperProcess n'est pas un test: c'est un faux govulncheck. Il rend le
// flux place dans QUAERO_GVC_<GOOS>, ce qui verifie au passage que chaque
// systeme recoit bien son GOOS. Sans GOOS, c'est la machine. « !rien » imite
// un systeme sans paquet a compiler, « !panne » un echec, « !dort » un moteur
// qui depasse son delai.
func TestGvcHelperProcess(t *testing.T) {
	if os.Getenv("QUAERO_GVC_HELPER") != "1" {
		return
	}
	goos := os.Getenv("GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}
	switch out := os.Getenv("QUAERO_GVC_" + goos); out {
	case "!rien":
		os.Stderr.WriteString("go: downloading example.com/x v1.0.0\ngovulncheck: no packages matched the provided patterns\n")
		os.Exit(2)
	case "!dort":
		time.Sleep(time.Minute)
	case "!panne", "":
		os.Stderr.WriteString("govulncheck: loading packages: echec simule\n")
		os.Exit(1)
	default:
		os.Stdout.WriteString(out)
		os.Exit(0)
	}
}

// fakeGovulncheck rend un govulncheck dont chaque systeme repond par streams.
func fakeGovulncheck(t *testing.T, streams map[string]string) Govulncheck {
	t.Helper()
	t.Setenv("QUAERO_GVC_HELPER", "1")
	for _, sys := range []string{"linux", "darwin", "windows"} {
		t.Setenv("QUAERO_GVC_"+sys, streams[sys])
	}
	return Govulncheck{Bin: os.Args[0], pre: []string{"-test.run=^TestGvcHelperProcess$", "--"}}
}

const (
	sbomStream = `{"SBOM":{"go_version":"go1.27.2","modules":[{"path":"example.com/app"},{"path":"golang.org/x/sys","version":"v0.30.0"},{"path":"stdlib","version":"v1.27.2"}]}}
`
	gvcOSVEntry = `{"osv":{"id":"GO-2026-1","summary":"Faille de x/sys","aliases":["CVE-2026-1"]}}
`
	gvcCalled = `{"finding":{"osv":"GO-2026-1","fixed_version":"v0.31.0","trace":[{"module":"golang.org/x/sys","version":"v0.30.0","package":"golang.org/x/sys/unix","function":"Open","position":{"filename":"main.go","line":7}}]}}
`
	gvcModuleOnly = `{"finding":{"osv":"GO-2026-1","trace":[{"module":"golang.org/x/sys","version":"v0.30.0"}]}}
`
)

// La machine passe d'abord, sans rien changer; les autres systemes viennent
// ensuite, sans cgo.
func TestSystemesMachineDAbord(t *testing.T) {
	got := systemsFor("windows")
	if len(got) != 3 || !got[0].native || got[0].goos != "windows" || got[0].label != "Windows" || got[1].goos != "linux" || got[2].goos != "darwin" {
		t.Errorf("systemes %+v", got)
	}
	if got := systemsFor("freebsd"); len(got) != 4 || got[0].goos != "freebsd" || !got[0].native {
		t.Errorf("machine hors des trois: %+v", got)
	}
	t.Setenv("CGO_ENABLED", "1")
	ctx := withScanEnv(context.Background(), hardenedEnv())
	cross := systemsFor("windows")[2].env(ctx)
	for key, want := range map[string]string{"GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"} {
		if got := runEnvHelper(t, cross, key); got != want {
			t.Errorf("%s = %q, attendu %q", key, got, want)
		}
	}
	native := systemsFor(runtime.GOOS)[0].env(context.Background())
	if got := runEnvHelper(t, native, "CGO_ENABLED"); got != "1" {
		t.Errorf("machine: CGO_ENABLED = %q, attendu inchange", got)
	}
}

// Le code fautif appele sous Linux seulement reste appele: analyse depuis
// Windows, il passait pour non appele.
func TestGovulncheckParSysteme(t *testing.T) {
	g := fakeGovulncheck(t, map[string]string{
		"linux":   sbomStream + gvcOSVEntry + gvcModuleOnly + gvcCalled,
		"darwin":  "!rien",
		"windows": sbomStream + gvcOSVEntry + gvcModuleOnly,
	})
	fs, facts, err := g.ScanBuild(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != "QRO-VULN-GO-2026-1" {
		t.Fatalf("constats %+v", fs)
	}
	f := fs[0]
	if f.Severity != finding.SeverityHigh || !hasContext(f, ContextCalled) || hasContext(f, ContextNotCalled) {
		t.Errorf("appel sous Linux perdu: %s %v", f.Severity, Contexts(f))
	}
	if !strings.Contains(f.Observed, "sous Linux:") {
		t.Errorf("systeme absent de l'observation: %q", f.Observed)
	}
	if facts == nil || facts.goVersion != "go1.27.2" {
		t.Errorf("version de Go: %+v", facts)
	}
}

// Un systeme en echec n'efface pas les autres, et le rapport le dit.
func TestGovulncheckSystemeEnEchec(t *testing.T) {
	g := fakeGovulncheck(t, map[string]string{
		"linux":   sbomStream + gvcOSVEntry + gvcModuleOnly,
		"darwin":  "!panne",
		"windows": sbomStream + gvcOSVEntry + gvcModuleOnly,
	})
	fs, _, err := g.ScanBuild(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[1].ID != "QRO-SCAN-PARTIEL-govulncheck" || !strings.Contains(fs[1].Observed, "macOS: ") || !strings.Contains(fs[1].Observed, "echec simule") {
		t.Fatalf("echec de macOS non dit: %+v", fs)
	}
	if !hasContext(fs[0], ContextNotCalled) {
		t.Errorf("constat des autres systemes perdu: %+v", fs[0])
	}
}

// Tous en echec: le moteur est en panne. Rien a compiler nulle part: rien n'a
// ete verifie, et le rapport le dit aussi.
func TestGovulncheckRienNulle(t *testing.T) {
	g := fakeGovulncheck(t, map[string]string{"linux": "!panne", "darwin": "!panne", "windows": "!panne"})
	if _, _, err := g.ScanBuild(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "macOS: ") {
		t.Errorf("panne non rendue: %v", err)
	}
	g = fakeGovulncheck(t, map[string]string{"linux": "!rien", "darwin": "!rien", "windows": "!rien"})
	fs, _, err := g.ScanBuild(context.Background(), t.TempDir())
	if err != nil || len(fs) != 1 || fs[0].ID != "QRO-SCAN-VIDE-govulncheck" {
		t.Errorf("rien a compiler: %v %+v", err, fs)
	}
}

// Le delai tombe apres la machine: son analyse reste, et le rapport dit ce qui
// a ete interrompu au lieu de passer le moteur en echec.
func TestGovulncheckDelaiGardeLaMachine(t *testing.T) {
	streams := map[string]string{"linux": "!dort", "darwin": "!dort", "windows": "!dort"}
	streams[runtime.GOOS] = sbomStream + gvcOSVEntry + gvcCalled
	g := fakeGovulncheck(t, streams)
	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{Timeout: 6 * time.Second}, g)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]finding.Finding{}
	for _, f := range rep.Findings {
		ids[f.ID] = f
	}
	if _, ok := ids["QRO-VULN-GO-2026-1"]; !ok {
		t.Fatalf("analyse de la machine perdue: %+v", rep.Findings)
	}
	if p, ok := ids["QRO-SCAN-PARTIEL-govulncheck"]; !ok || !strings.Contains(p.Observed, "delai maximal") {
		t.Errorf("interruption non dite: %+v", rep.Findings)
	}
	if _, ok := ids["QRO-SCAN-ERREUR-govulncheck"]; ok {
		t.Error("moteur passe en echec")
	}
}

func TestDirectivesRequire(t *testing.T) {
	text := "module m\ngo 1.25\nrequire a v1\nrequire \"q\" v1.0.0 // indirect\nrequire (\n\tc v1\n\te v2 // indirect\n)\n// require z v1\nreplace x => y v1\nrequire( f v1 )\n"
	if got, want := requiredModules(text), []string{"a", "q", "c", "e", "f"}; !reflect.DeepEqual(got, want) {
		t.Errorf("%v, attendu %v", got, want)
	}
}

func TestReponseGoModWhy(t *testing.T) {
	out := "# golang.org/x/crypto\r\n(main module does not need module golang.org/x/crypto)\r\n\r\n# golang.org/x/sys\r\nexample.com/app\r\ngolang.org/x/sys/unix\r\n"
	if got, want := parseWhy(out), map[string]bool{"golang.org/x/crypto": true, "golang.org/x/sys": false}; !reflect.DeepEqual(got, want) {
		t.Errorf("%v, attendu %v", got, want)
	}
}

// Ce que go mod tidy -diff ecrit pour un go.mod dont un module ne sert plus,
// et dont un autre change seulement de bloc.
func TestDiffDeTidy(t *testing.T) {
	out := "diff current/go.mod tidy/go.mod\r\n--- current/go.mod\r\n+++ tidy/go.mod\r\n@@ -2,12 +2,9 @@\r\n \r\n go 1.21\r\n \r\n-require (\r\n-\texample.com/used v0.0.0\r\n-\texample.com/dead v0.0.0 // indirect\r\n-)\r\n+require example.com/used v0.0.0\r\n-require example.com/old v1.0.0\r\n \r\n replace (\r\n-\texample.com/used => ./used\r\n+\texample.com/used => ./used\r\n )\r\n-toolchain go1.27.2\r\n\r\ndiff current/go.sum tidy/go.sum\r\n--- current/go.sum\r\n+++ tidy/go.sum\r\n-example.com/gone v1.0.0 h1:abc=\r\n"
	if got, want := parseTidyDiff(out), map[string]bool{"example.com/dead": true, "example.com/old": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("%v, attendu %v", got, want)
	}
}

// writeModule ecrit un petit module dont chaque dependance est un dossier
// voisin, pour que go travaille sans reseau.
func writeModule(t *testing.T, root, gomodExtra string, files map[string]string, deps ...string) string {
	t.Helper()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gomod := "module example.com/app\n\ngo 1.21\n\nrequire (\n"
	for _, m := range deps {
		gomod += "\texample.com/" + m + " v0.0.0\n"
		write(m+"/go.mod", "module example.com/"+m+"\n\ngo 1.21\n")
		write(m+"/"+m+".go", "package "+m+"\n\nfunc F() {}\n")
	}
	gomod += gomodExtra + ")\n\nreplace (\n"
	for _, m := range deps {
		gomod += "\texample.com/" + m + " => ./" + m + "\n"
	}
	gomod += ")\n"
	write("go.mod", gomod)
	for rel, body := range files {
		write(rel, body)
	}
	return gomod
}

func offlineGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go absent")
	}
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
}

// Le vrai go, sur un petit module: un import reserve a Linux et un import de
// test comptent, quel que soit le systeme qui lance le test. Rien n'est ecrit.
func TestModulesInutilisesReel(t *testing.T) {
	offlineGo(t)
	root := t.TempDir()
	gomod := writeModule(t, root, "", map[string]string{
		"main.go":      "package main\n\nimport \"example.com/used\"\n\nfunc main() { used.F() }\n",
		"sys_linux.go": "//go:build linux\n\npackage main\n\nimport \"example.com/linuxonly\"\n\nvar _ = linuxonly.F\n",
		"main_test.go": "package main\n\nimport (\n\t\"testing\"\n\n\t\"example.com/testonly\"\n)\n\nfunc TestX(t *testing.T) { testonly.F() }\n",
	}, "used", "linuxonly", "testonly", "dead")

	got := unusedModules(context.Background(), root)
	if want := map[string]bool{"example.com/dead": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("inutilises: %v, attendu %v", got, want)
	}
	if after, _ := os.ReadFile(filepath.Join(root, "go.mod")); string(after) != gomod {
		t.Error("go.mod modifie")
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); err == nil {
		t.Error("go.sum ecrit")
	}

	// Vendorise: pas de reponse, plutot que des telechargements.
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unusedModules(context.Background(), root); got != nil {
		t.Errorf("depot vendorise: %v", got)
	}
}

// Un module importe mais introuvable: go mod why le dirait inutile sans
// erreur. tidy -diff echoue, et rien n'est dit.
func TestModuleIntrouvableJamaisInutile(t *testing.T) {
	offlineGo(t)
	root := t.TempDir()
	writeModule(t, root, "\texample.com/remote v1.0.0\n", map[string]string{
		"main.go": "package main\n\nimport (\n\t\"example.com/remote/pkg\"\n\t\"example.com/used\"\n)\n\nfunc main() { used.F(); pkg.F() }\n",
	}, "used", "dead")
	if got := unusedModules(context.Background(), root); got != nil {
		t.Errorf("reponse malgre un module introuvable: %v", got)
	}
}

// buildFake est un govulncheck injecte qui rend directement ce qu'il sait.
type buildFake struct {
	fakeScanner
	facts *goFacts
}

func (b buildFake) ScanBuild(context.Context, string) ([]finding.Finding, *goFacts, error) {
	return b.findings, b.facts, b.err
}

func osvDep(module, version, manifest string, ids ...string) finding.Finding {
	f := finding.Finding{ID: "QRO-OSV-" + ids[0] + "-" + module, Severity: finding.SeverityMedium, Status: finding.StatusReview}
	for _, id := range ids {
		f.References = append(f.References, osvRef(id))
	}
	f.Evidence = []finding.Evidence{{Type: "manifest", Data: manifest}}
	f.Target = &finding.Target{Type: "dependency", Identifier: module + "@" + version}
	return f
}

// Une dependance que rien n'importe se range a part, sans rien perdre. Une
// vulnerabilite partagee avec stdlib, un autre go.mod ou un module importe ne
// s'y range pas, meme fusionnee sous le nom du module inutilise.
func TestDependanceInutilisee(t *testing.T) {
	osv := fakeScanner{name: "osv-scanner", available: true, findings: []finding.Finding{
		osvDep("golang.org/x/crypto", "0.33.0", "go.mod", "GO-A"),
		osvDep("golang.org/x/crypto", "0.33.0", "go.mod", "GO-B", "CVE-B"),
		osvDep("golang.org/x/sys", "0.30.0", "go.mod", "GO-C"),
		// GO-D touche x/crypto et stdlib: dedupe les fusionne.
		osvDep("golang.org/x/crypto", "0.33.0", "go.mod", "GO-D"),
		osvDep("stdlib", "1.25", "go.mod", "GO-D"),
		// GO-E: x/crypto ici, x/net dans un autre go.mod, relies par un alias.
		osvDep("golang.org/x/crypto", "0.33.0", "go.mod", "GO-E"),
		osvDep("golang.org/x/net", "0.35.0", "tools/go.mod", "GHSA-E", "GO-E"),
	}}
	unused := map[string]bool{"golang.org/x/crypto": true, "golang.org/x/net": true}
	gvc := buildFake{fakeScanner: fakeScanner{name: "govulncheck", available: true}, facts: &goFacts{goVersion: "go1.27.2", unused: unused}}

	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{}, osv, gvc)
	if err != nil {
		t.Fatal(err)
	}
	tagged := map[string]bool{}
	for _, f := range rep.Findings {
		if hasContext(f, ContextUnused) {
			tagged[f.References[0].ID] = true
		}
	}
	if want := map[string]bool{"GO-A": true, "GO-B": true}; !reflect.DeepEqual(tagged, want) {
		t.Errorf("inutilisees: %v, attendu %v", tagged, want)
	}
	if got := rep.Run.Context["go_compile"]; got != "go1.27.2" {
		t.Errorf("version de Go: %v", got)
	}
	if !OffProduct(ContextUnused) {
		t.Error("dependance inutilisee non rangee a part")
	}
}
