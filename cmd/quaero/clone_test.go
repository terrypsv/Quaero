// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/repo"
)

// Le clone est superficiel et prudent: une branche, pas d'etiquettes, pas de
// hooks, pas de sous-modules par le protocole fichier.
func TestCloneArgs(t *testing.T) {
	args := strings.Join(cloneArgs("https://github.com/a/b.git", "/tmp/x"), " ")
	for _, want := range []string{"--depth 1", "--single-branch", "--no-tags", "core.hooksPath=", "protocol.file.allow=never"} {
		if !strings.Contains(args, want) {
			t.Errorf("arguments de clone sans %q: %s", want, args)
		}
	}
	// Le dossier cible est le dernier argument, l'URL juste avant.
	if args := cloneArgs("URL", "DIR"); args[len(args)-1] != "DIR" || args[len(args)-2] != "URL" {
		t.Errorf("ordre des arguments: %v", args)
	}
}

// Un dossier local l'emporte sur une reference de depot de meme forme.
func TestResolveScanTargetLocalDAbord(t *testing.T) {
	dir := t.TempDir()
	got, label, untrusted, cleanup, err := resolveScanTarget(t.Context(), dir)
	defer cleanup()
	if err != nil {
		t.Fatalf("resolveScanTarget: %v", err)
	}
	if got != dir || untrusted || label != dir {
		t.Errorf("dossier local lu comme %q, non_fiable=%v", got, untrusted)
	}
}

func TestResolveScanTargetInvalide(t *testing.T) {
	_, _, _, cleanup, err := resolveScanTarget(t.Context(), "pas-un-depot")
	defer cleanup()
	if err == nil {
		t.Error("une cible qui n'est ni dossier ni depot doit echouer")
	}
}

// Aucun gestionnaire d'identifiants: ni fenetre de connexion, ni identifiant
// enregistre utilise sans que l'utilisateur l'ait donne a Quaero.
func TestCloneSansGestionnaireDIdentifiants(t *testing.T) {
	args := strings.Join(cloneArgs("https://github.com/a/b.git", "DIR"), " ")
	for _, want := range []string{
		"credential.helper=", "core.askPass=", "protocol.allow=never", "protocol.https.allow=always",
		"url.https://github.com/a/b.git.insteadOf=https://github.com/a/b.git",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("clone sans %q: %s", want, args)
		}
	}
	if env := strings.Join(cloneEnv(""), "\n"); !strings.Contains(env, "\nGIT_ASKPASS=\n") && !strings.HasSuffix(env, "\nGIT_ASKPASS=") {
		t.Error("GIT_ASKPASS non neutralise")
	}
}

// Le jeton passe par l'environnement, jamais par la ligne de commande, et
// seulement vers github.com.
func TestCloneEnvJeton(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", " 2 ")
	without := strings.Join(cloneEnv(""), "\n")
	if strings.Contains(without, "AUTHORIZATION") {
		t.Error("en-tete d'authentification pose sans jeton")
	}
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never", "GIT_LFS_SKIP_SMUDGE=1"} {
		if !strings.Contains(without, want) {
			t.Errorf("environnement sans %s", want)
		}
	}
	with := strings.Join(cloneEnv("jeton-secret"), "\n")
	if strings.Contains(with, "jeton-secret") {
		t.Error("le jeton apparait en clair dans l'environnement")
	}
	// Les reglages git deja dans l'environnement sont gardes, l'en-tete vient
	// a leur suite.
	for _, want := range []string{"GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_2=http.https://github.com/.extraheader", "GIT_CONFIG_VALUE_2=AUTHORIZATION: basic "} {
		if !strings.Contains(with, want) {
			t.Errorf("environnement sans %s", want)
		}
	}
}

// fakeGit ecrit un faux git qui clone en anonyme si anon vaut 1, et sinon
// seulement avec un en-tete d'authentification. Il note dans log si un
// en-tete lui a ete passe.
func fakeGit(t *testing.T, anon, withHeader string) (git, log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("faux git en script shell")
	}
	dir := t.TempDir()
	git = filepath.Join(dir, "git")
	log = filepath.Join(dir, "log")
	script := `#!/bin/sh
for last; do :; done
auth=$(env | grep -c "^GIT_CONFIG_VALUE_[0-9]*=AUTHORIZATION: basic ")
if [ "$auth" != 0 ]; then echo jeton >> "` + log + `"; else echo anonyme >> "` + log + `"; fi
if [ "$auth" = 0 ] && [ "` + anon + `" = 1 ]; then mkdir -p "$last/.git"; exit 0; fi
if [ "$auth" != 0 ]; then
  if [ "` + withHeader + `" = ok ]; then mkdir -p "$last/.git"; exit 0; fi
  echo "remote: Repository not found." >&2; echo "fatal: repository 'https://github.com/a/b.git/' not found" >&2; exit 128
fi
mkdir -p "$last/.git/partiel"
echo "fatal: could not read Username for 'https://github.com': terminal prompts disabled" >&2
exit 128
`
	if err := os.WriteFile(git, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return git, log
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

var ref = repo.Ref{Owner: "a", Name: "b"}

// Un depot public se clone sans jeton, meme quand un jeton existe.
func TestClonePublicSansJeton(t *testing.T) {
	git, log := fakeGit(t, "1", "ok")
	dir, cleanup, err := cloneWith(t.Context(), git, ref, "jeton")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if got := readLog(t, log); got != "anonyme" {
		t.Errorf("tentatives: %q, attendu un seul clone anonyme", got)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("clone non efface: %s", dir)
	}
}

// Un depot prive se clone avec le jeton, apres le refus anonyme, dans un
// dossier repris a vide.
func TestClonePriveAvecJeton(t *testing.T) {
	git, log := fakeGit(t, "0", "ok")
	dir, cleanup, err := cloneWith(t.Context(), git, ref, "jeton")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := readLog(t, log); got != "anonyme\njeton" {
		t.Errorf("tentatives: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "partiel")); !os.IsNotExist(err) {
		t.Error("le reste du clone anonyme n'a pas ete efface")
	}
}

// Sans jeton, ou avec un jeton qui n'y a pas acces, l'erreur dit quoi faire,
// et rien ne reste sur le disque.
func TestClonePriveRefuse(t *testing.T) {
	for _, c := range []struct{ token, want string }{
		{"", "quaero -save-token"},
		{"jeton", "hors de portee du jeton"},
	} {
		git, _ := fakeGit(t, "0", "non")
		_, _, err := cloneWith(t.Context(), git, ref, c.token)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("jeton %q: %v, attendu %q", c.token, err, c.want)
		}
	}
}

func TestStaleClones(t *testing.T) {
	tmp := t.TempDir()
	old := filepath.Join(tmp, cloneDirPrefix+"vieux")
	fresh := filepath.Join(tmp, cloneDirPrefix+"recent")
	other := filepath.Join(tmp, "autre-vieux")
	for _, d := range []string{old, fresh, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	for _, d := range []string{old, other} {
		if err := os.Chtimes(d, past, past); err != nil {
			t.Fatal(err)
		}
	}
	got := staleClones(tmp, time.Hour)
	if len(got) != 1 || got[0] != old {
		t.Errorf("clones oublies: %v, attendu [%s]", got, old)
	}
}

func TestGitFailure(t *testing.T) {
	for out, want := range map[string]string{
		"Cloning into 'x'...\nremote: oups\nfatal: unable to access 'u': 403\n": "fatal: unable to access 'u': 403",
		"Cloning into 'x'...\nerror: quelque chose\n":                           "error: quelque chose",
		"": "erreur inconnue",
	} {
		if got := gitFailure(out); got != want {
			t.Errorf("gitFailure(%q) = %q, attendu %q", out, got, want)
		}
	}
}
