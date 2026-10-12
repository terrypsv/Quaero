// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"strings"
	"testing"
)

func TestParseRepoRef(t *testing.T) {
	cases := map[string]string{
		"mushorg/cowrie":                        "mushorg/cowrie",
		"https://github.com/mushorg/cowrie":     "mushorg/cowrie",
		"https://github.com/mushorg/cowrie.git": "mushorg/cowrie",
		"http://github.com/mushorg/cowrie/":     "mushorg/cowrie",
		"github.com/mushorg/cowrie":             "mushorg/cowrie",
		"www.github.com/mushorg/cowrie":         "mushorg/cowrie",
		"git@github.com:mushorg/cowrie.git":     "mushorg/cowrie",
		"terrypsv/Quaero":                       "terrypsv/Quaero",
		"a/b.c-d_e":                             "a/b.c-d_e",
	}
	for in, want := range cases {
		ref, ok := parseRepoRef(in)
		if !ok {
			t.Errorf("%q refuse, attendu %s", in, want)
			continue
		}
		if ref.String() != want {
			t.Errorf("%q -> %s, attendu %s", in, ref, want)
		}
	}
}

func TestParseRepoRefRejette(t *testing.T) {
	for _, in := range []string{
		"", "cowrie", "mushorg/cowrie/extra", "gitlab.com/a/b",
		"https://evil.com/a/b", "../etc/passwd", "a/..", "a/.",
		"a b/c", "mushorg/cow rie", "/absolute/path",
	} {
		if ref, ok := parseRepoRef(in); ok {
			t.Errorf("%q accepte comme %s, attendu un refus", in, ref)
		}
	}
}

// Seul github.com, en HTTPS, est clone.
func TestCloneURL(t *testing.T) {
	ref, _ := parseRepoRef("mushorg/cowrie")
	if got := ref.cloneURL(); got != "https://github.com/mushorg/cowrie.git" {
		t.Errorf("URL de clone = %q", got)
	}
}

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
