// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func TestFiltresLicenceAuteurListesTransmis(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	out := search(t, newServer(f), quick("/api/search?q=honeypot&license=MIT&owner=mushorg&nolists=1"))
	for _, want := range []string{"license:mit", "user:mushorg", "NOT awesome", "-topic:awesome-list"} {
		if !strings.Contains(f.lastQuery, want) {
			t.Errorf("requete %q sans %s", f.lastQuery, want)
		}
	}
	if got := out.Intent.Filters; got.License != "mit" || got.Owner != "mushorg" || !got.NoLists {
		t.Errorf("filtres renvoyes = %+v", got)
	}
}

func TestFiltresLicenceAuteurInvalides(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	out := search(t, newServer(f), quick("/api/search?q=honeypot&license=NOASSERTION&owner=a+b:c&nolists=oui"))
	if got := out.Intent.Filters; got.License != "" || got.Owner != "" || got.NoLists {
		t.Errorf("filtres invalides acceptes: %+v", got)
	}
	for _, bad := range []string{"license:", "user:", "awesome"} {
		if strings.Contains(f.lastQuery, bad) {
			t.Errorf("requete %q contient %s", f.lastQuery, bad)
		}
	}
}

// L'exclusion tient quelle que soit la requete qui a trouve le depot: la
// strategie par sujet n'a pas de NOT, le serveur retire donc lui-meme les
// depots qui portent le mot ecarte, et les listes quand on les ecarte.
func TestExclusionAppliqueeAuxResultats(t *testing.T) {
	f := &fakeSearcher{total: 4, repos: []model.Repo{
		{FullName: "cowrie/cowrie", Name: "cowrie", Description: "SSH honeypot"},
		{FullName: "x/ssh-pot", Name: "ssh-pot", Description: "Honeypot, a lighter take on Cowrie"},
		{FullName: "y/awesome-honeypots", Name: "awesome-honeypots", Description: "A curated list"},
		{FullName: "z/hp", Name: "hp", Description: "Honeypot for google cloud", Topics: []string{"honeypot"}},
	}}
	out := search(t, newServer(f), "/api/search?q=pot+de+miel+sauf+cowrie&nolists=1")
	var names []string
	for _, r := range out.Repos {
		names = append(names, r.FullName)
	}
	if len(out.Repos) != 1 || out.Repos[0].FullName != "z/hp" {
		t.Errorf("depots gardes = %v, attendu z/hp seul", names)
	}
}

// Un mot ecarte l'est en entier: ecarter go n'ecarte pas google.
func TestExclusionMotEntier(t *testing.T) {
	r := model.Repo{Name: "hp", Description: "Honeypot for google cloud"}
	if mentions(r, []string{"go"}) {
		t.Error("go trouve dans google")
	}
	if !mentions(model.Repo{Name: "x", Description: "Enumerate Active Directory"}, []string{"active-directory"}) {
		t.Error("active-directory doit correspondre a Active Directory")
	}
}

// La lecture se demande sans rien depenser: aucun appel a GitHub.
func TestLectureSansAppel(t *testing.T) {
	f := &fakeSearcher{}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/read?q=pot+de+miel+ssh+en+go,+pas+de+cowrie", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if f.calls != 0 {
		t.Errorf("%d appel(s) a GitHub pour une simple lecture", f.calls)
	}
	var out struct {
		Intent model.Intent `json:"intent"`
		Query  string       `json:"query"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Intent.Language != "Go" || !strings.Contains(out.Query, "NOT cowrie") || !strings.Contains(out.Query, "honeypot") {
		t.Errorf("lecture = %+v, requete = %q", out.Intent, out.Query)
	}
}

func TestLectureEnFrancais(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/read?q=chiffrement+de+fichiers&scope=francais", nil))
	if !strings.Contains(rec.Body.String(), "chiffrement") || strings.Contains(rec.Body.String(), "encryption") {
		t.Errorf("lecture en francais = %s", rec.Body.String())
	}
}

func TestLectureSansPhrase(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/read?q=+", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, attendu 400", rec.Code)
	}
}
