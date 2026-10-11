// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package github

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// L'ordre de lecture du jeton est la cle du diagnostic: la variable gagne sur
// le fichier, et la source retenue est celle que le message d'erreur nommera.
func TestResolveTokenOrdreEtSource(t *testing.T) {
	withHome(t)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	if tok, src := resolveToken(); tok != "" || src != "" {
		t.Fatalf("rien de configure: obtenu %q depuis %q", tok, src)
	}
	if _, err := SaveToken("depuis-fichier"); err != nil {
		t.Fatal(err)
	}
	if tok, src := resolveToken(); tok != "depuis-fichier" || src != SourceFile {
		t.Errorf("fichier seul: obtenu %q depuis %q", tok, src)
	}
	t.Setenv("GH_TOKEN", " depuis-gh ")
	if tok, src := resolveToken(); tok != "depuis-gh" || src != SourceGHToken {
		t.Errorf("GH_TOKEN devant le fichier: obtenu %q depuis %q", tok, src)
	}
	t.Setenv("GITHUB_TOKEN", "depuis-github")
	if tok, src := resolveToken(); tok != "depuis-github" || src != SourceGitHubToken {
		t.Errorf("GITHUB_TOKEN devant tout: obtenu %q depuis %q", tok, src)
	}
}

// Un jeton refuse doit designer l'endroit ou il a ete lu, pas une variable
// qui n'est peut-etre meme pas definie.
func TestJetonRefuseNommeSaSource(t *testing.T) {
	home := withHome(t)
	cases := []struct {
		source  string
		attendu []string
		absent  string
	}{
		{SourceFile, []string{home, "-save-token", "-forget-token"}, "GITHUB_TOKEN"},
		{SourceGHToken, []string{"variable GH_TOKEN"}, "-forget-token"},
		{SourceGitHubToken, []string{"variable GITHUB_TOKEN"}, "-forget-token"},
		{"", []string{"GITHUB_TOKEN", "GH_TOKEN", "-save-token"}, ""},
	}
	for _, tc := range cases {
		c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		})
		c.Source = tc.source
		_, _, _, err := c.Search(context.Background(), "x", 10, 1)
		srv.Close()
		if err == nil {
			t.Fatalf("source %q: erreur attendue", tc.source)
		}
		msg := err.Error()
		if !strings.Contains(msg, "Bad credentials") {
			t.Errorf("source %q: la reponse de GitHub doit rester citee: %q", tc.source, msg)
		}
		for _, a := range tc.attendu {
			if !strings.Contains(msg, a) {
				t.Errorf("source %q: %q absent de %q", tc.source, a, msg)
			}
		}
		if tc.absent != "" && strings.Contains(msg, tc.absent) {
			t.Errorf("source %q: %q ne devrait pas apparaitre dans %q", tc.source, tc.absent, msg)
		}
	}
}
