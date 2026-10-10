// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeEngine depose un faux binaire executable nomme name dans dir et rend son
// chemin. Sous Windows il porte l'extension .exe, comme un `go install` reel.
func fakeEngine(t *testing.T, dir, name string) string {
	t.Helper()
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	full := filepath.Join(dir, file)
	if err := os.WriteFile(full, []byte("x"), 0o755); err != nil {
		t.Fatalf("ecriture du faux moteur: %v", err)
	}
	return full
}

// isolate vide le PATH et pointe les dossiers d'installation vers des dossiers
// temporaires vides, pour que le test ne depende pas de la machine qui le lance.
func isolate(t *testing.T) {
	t.Helper()
	empty := t.TempDir()
	t.Setenv("PATH", "")
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", empty)
	t.Setenv("HOME", empty)
	t.Setenv("USERPROFILE", empty)
}

func TestResolveBinFallbackGOBIN(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	want := fakeEngine(t, dir, "quaero-faux-moteur")
	t.Setenv("GOBIN", dir)

	got, err := resolveBin("quaero-faux-moteur")
	if err != nil {
		t.Fatalf("moteur hors PATH non trouve dans GOBIN: %v", err)
	}
	if !samePath(got, want) {
		t.Errorf("chemin = %q, attendu %q", got, want)
	}
}

func TestResolveBinFallbackHomeGoBin(t *testing.T) {
	// Le cas reel du poste Windows: GOBIN et GOPATH non definis, les binaires
	// de `go install` sont dans le dossier utilisateur, sous go\bin.
	isolate(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GOPATH", "")
	bin := filepath.Join(home, "go", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	want := fakeEngine(t, bin, "quaero-faux-moteur")

	got, err := resolveBin("quaero-faux-moteur")
	if err != nil {
		t.Fatalf("moteur non trouve dans ~/go/bin: %v", err)
	}
	if !samePath(got, want) {
		t.Errorf("chemin = %q, attendu %q", got, want)
	}
}

func TestResolveBinAbsentDitOuIlACherche(t *testing.T) {
	isolate(t)
	_, err := resolveBin("quaero-moteur-inexistant")
	if err == nil {
		t.Fatal("un moteur absent partout devrait etre une erreur")
	}
	if !strings.Contains(err.Error(), "introuvable dans le PATH et dans") {
		t.Errorf("message peu utile pour diagnostiquer: %v", err)
	}
}

func TestAvailableUtiliseLaResolution(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	fakeEngine(t, dir, "quaero-faux-moteur")
	t.Setenv("GOBIN", dir)

	if !(Gosec{Bin: "quaero-faux-moteur"}).Available() {
		t.Error("Available() doit voir un moteur pose dans GOBIN hors PATH")
	}
}

func TestInstallDirsSansDoublon(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	t.Setenv("GOBIN", filepath.Join(dir, "bin"))
	t.Setenv("GOPATH", dir) // GOPATH\bin == GOBIN

	seen := map[string]int{}
	for _, d := range installDirs() {
		seen[strings.ToLower(filepath.Clean(d))]++
	}
	for d, n := range seen {
		if n > 1 {
			t.Errorf("%s liste %d fois", d, n)
		}
	}
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
