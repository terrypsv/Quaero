// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package repo

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]string{
		"mushorg/cowrie":                        "mushorg/cowrie",
		"https://github.com/mushorg/cowrie":     "mushorg/cowrie",
		"https://github.com/mushorg/cowrie.git": "mushorg/cowrie",
		"http://github.com/mushorg/cowrie/":     "mushorg/cowrie",
		"github.com/mushorg/cowrie":             "mushorg/cowrie",
		"www.github.com/mushorg/cowrie":         "mushorg/cowrie",
		"git@github.com:mushorg/cowrie.git":     "mushorg/cowrie",
		"  terrypsv/Quaero  ":                   "terrypsv/Quaero",
		"a/b.c-d_e":                             "a/b.c-d_e",
		"HTTPS://GitHub.com/mushorg/cowrie":     "mushorg/cowrie",
	}
	for in, want := range cases {
		ref, ok := Parse(in)
		if !ok {
			t.Errorf("%q refuse, attendu %s", in, want)
			continue
		}
		if ref.String() != want {
			t.Errorf("%q -> %s, attendu %s", in, ref, want)
		}
	}
}

func TestParseRejette(t *testing.T) {
	for _, in := range []string{
		"", "cowrie", "mushorg/cowrie/extra", "gitlab.com/a/b",
		"https://evil.com/a/b", "../etc/passwd", "a/..", "a/.", "a/...",
		"a b/c", "mushorg/cow rie", "/absolute/path", `C:\Users\moi\projet`,
		"-a/b", "a-/b", "https://github.com/a/b?x=1", "https://github.com/a/b#x",
		"file:///etc/passwd", "--upload-pack=x/y",
	} {
		if ref, ok := Parse(in); ok {
			t.Errorf("%q accepte comme %s, attendu un refus", in, ref)
		}
	}
}

// Les adresses derivees ne pointent que sur github.com, en HTTPS.
func TestAdresses(t *testing.T) {
	ref, _ := Parse("mushorg/cowrie")
	for got, want := range map[string]string{
		ref.URL():       "https://github.com/mushorg/cowrie",
		ref.CloneURL():  "https://github.com/mushorg/cowrie.git",
		ref.ReportURL(): "https://github.com/mushorg/cowrie/security/advisories/new",
	} {
		if got != want {
			t.Errorf("%q, attendu %q", got, want)
		}
	}
}
