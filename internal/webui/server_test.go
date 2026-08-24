// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/model"
)

type fakeSearcher struct {
	repos     []model.Repo
	total     int
	rate      github.RateLimit
	err       error
	lastQuery string
	lastPage  int
	calls     int
	// emptyUntil makes the first N calls return nothing, so the relaxation
	// ladder can be observed.
	emptyUntil int
}

func (f *fakeSearcher) Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error) {
	f.lastQuery = query
	f.lastPage = page
	f.calls++
	if f.calls <= f.emptyUntil {
		return nil, 0, f.rate, nil
	}
	return f.repos, f.total, f.rate, f.err
}

func newServer(f *fakeSearcher) http.Handler {
	return (&Server{Client: f, Version: "test"}).Handler()
}

// quick appends the parameter that keeps a test to a single API call, so that
// assertions about "the query sent" stay unambiguous.
func quick(url string) string { return url + "&precision=rapide" }

func TestIndexIsServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Quaero") {
		t.Error("la page ne contient pas le titre")
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ailleurs", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", rec.Code)
	}
}

func TestSearchRequiresQuery(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/search", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rec.Code)
	}
}

func TestSearchTranslatesPhraseToQualifiers(t *testing.T) {
	// Un total non nul evite de declencher l'echelle de desserrage, qui
	// ecraserait la requete observee par sa version relachee.
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		quick("/api/search?q=une+bibliotheque+go+pour+yaml,+maintenue"), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"language:Go", "pushed:>=", "fork:false"} {
		if !strings.Contains(f.lastQuery, want) {
			t.Errorf("requete %q ne contient pas %q", f.lastQuery, want)
		}
	}
}

func TestSearchReturnsIntentAndQuery(t *testing.T) {
	// Renvoyer la requete construite est ce qui permet a l'utilisateur de
	// comprendre un resultat surprenant plutot que de le subir.
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		quick("/api/search?q=outil+rust"), nil))

	var out model.Result
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if out.Query == "" {
		t.Error("la requete construite doit etre renvoyee")
	}
	if out.Intent.Language != "Rust" {
		t.Errorf("langage = %q, want Rust", out.Intent.Language)
	}
}

func TestSearchRanksResults(t *testing.T) {
	f := &fakeSearcher{
		total: 2,
		repos: []model.Repo{
			{FullName: "big/other", Name: "other", Stars: 90000, PushedAt: time.Now()},
			{FullName: "small/yaml", Name: "yaml", Stars: 100, PushedAt: time.Now()},
		},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if len(out.Repos) != 2 {
		t.Fatalf("resultats = %d", len(out.Repos))
	}
	if out.Repos[0].Name != "yaml" {
		t.Errorf("premier = %q, le classement n'a pas ete applique", out.Repos[0].Name)
	}
	if out.Repos[0].Health.Level == "" {
		t.Error("la sante doit etre renseignee")
	}
}

func TestUpstreamErrorSurfacesTheQuery(t *testing.T) {
	f := &fakeSearcher{err: fmt.Errorf("quota epuise")}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml"), nil))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", rec.Code)
	}
	var payload map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&payload)
	if payload["error"] == nil || payload["query"] == nil {
		t.Errorf("l'erreur doit exposer la requete envoyee: %v", payload)
	}
}

func TestLowQuotaIsAnnounced(t *testing.T) {
	// Un quota qui va manquer change ce que l'utilisateur doit faire ensuite;
	// il vaut mieux le dire que le lui faire decouvrir par un echec.
	f := &fakeSearcher{
		total: 1,
		repos: []model.Repo{{FullName: "a/b", Name: "b"}},
		rate:  github.RateLimit{Remaining: 3, Limit: 5000, ResetAt: time.Now().Add(time.Hour)},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Note == "" {
		t.Error("un quota faible doit produire une note")
	}
}

func TestPaginationIsForwarded(t *testing.T) {
	f := &fakeSearcher{total: 1}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml&page=3"), nil))
	if f.lastPage != 3 {
		t.Errorf("page transmise = %d, want 3", f.lastPage)
	}
}

// Un total de onze mille correspondances ne veut pas dire onze mille resultats
// atteignables: l'API en restitue mille. Promettre des pages vides serait pire
// que d'annoncer la limite.
func TestUnreachableResultsAreAnnounced(t *testing.T) {
	f := &fakeSearcher{total: 11000, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Reachable != 1000 {
		t.Errorf("atteignables = %d, want 1000", out.Reachable)
	}
	if out.Total != 11000 {
		t.Errorf("total = %d, want 11000", out.Total)
	}
	if out.Note == "" {
		t.Error("l'ecart entre trouves et atteignables doit etre annonce")
	}
	if out.Pages != 20 {
		t.Errorf("pages = %d, want 20 (1000/50)", out.Pages)
	}
}

func TestSortModeIsApplied(t *testing.T) {
	f := &fakeSearcher{
		total: 2,
		repos: []model.Repo{
			{FullName: "a/small", Name: "yaml", Stars: 50, PushedAt: time.Now()},
			{FullName: "b/big", Name: "yaml", Stars: 90000, PushedAt: time.Now()},
		},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml&sort=populaire"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Sort != "populaire" {
		t.Errorf("tri = %q", out.Sort)
	}
	if out.Repos[0].Stars != 90000 {
		t.Error("le tri populaire doit placer le plus etoile en tete")
	}
}

func TestNicheSortSurfacesSmallProjects(t *testing.T) {
	f := &fakeSearcher{
		total: 2,
		repos: []model.Repo{
			{FullName: "b/big", Name: "yaml", Stars: 90000, PushedAt: time.Now()},
			{FullName: "a/small", Name: "yaml", Stars: 200, PushedAt: time.Now()},
		},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml&sort=niche"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out.Repos[0].Stars != 200 {
		t.Error("le tri niche doit remonter le projet cible")
	}
}

// Une page vide ne distingue pas "n'existe pas" de "requete trop serree": on
// desserre, et on dit ce qu'on a lache.
func TestEmptyResultTriggersRelaxation(t *testing.T) {
	f := &fakeSearcher{
		emptyUntil: 1,
		total:      3,
		repos:      []model.Repo{{FullName: "a/yaml", Name: "yaml", Stars: 10, PushedAt: time.Now()}},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		quick("/api/search?q=une+lib+go+pour+yaml,+maintenue,+populaire"), nil))

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)

	if f.calls < 2 {
		t.Errorf("appels = %d, le desserrage n'a pas eu lieu", f.calls)
	}
	if len(out.Repos) == 0 {
		t.Error("le desserrage devait finir par trouver quelque chose")
	}
	if out.Note == "" || !strings.Contains(out.Note, "desserr") && !strings.Contains(out.Note, "Rien trouve") {
		t.Errorf("le desserrage doit etre annonce: %q", out.Note)
	}
}

func TestRelaxationOnlyOnFirstPage(t *testing.T) {
	// Desserrer sur une page profonde melangerait deux jeux de resultats.
	f := &fakeSearcher{emptyUntil: 99}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		quick("/api/search?q=une+lib+go+pour+yaml,+maintenue&page=3"), nil))

	if f.calls != 1 {
		t.Errorf("appels = %d, aucun desserrage attendu au-dela de la page 1", f.calls)
	}
}

// Le mode approfondi doit reellement poser la question plusieurs fois, et un
// depot trouve par plusieurs formulations doit porter cet accord.
func TestDeepPrecisionMergesStrategies(t *testing.T) {
	f := &fakeSearcher{
		total: 1,
		repos: []model.Repo{{FullName: "a/yaml", Name: "yaml", Stars: 100, PushedAt: time.Now()}},
	}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/search?q=un+parser+yaml+en+go", nil))

	if f.calls < 4 {
		t.Errorf("appels = %d, le mode approfondi devait poser plusieurs questions", f.calls)
	}

	var out model.Result
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if len(out.Repos) != 1 {
		t.Fatalf("depots = %d, la fusion devait dedoublonner", len(out.Repos))
	}
	if len(out.Repos[0].FoundBy) < 2 {
		t.Errorf("provenance = %v, l'accord entre formulations devait etre conserve", out.Repos[0].FoundBy)
	}
	if len(out.Queries) < 4 {
		t.Errorf("requetes exposees = %d, elles doivent toutes etre inspectables", len(out.Queries))
	}
	if out.Precision != "approfondie" {
		t.Errorf("precision = %q", out.Precision)
	}
}

func TestQuickPrecisionAsksOnce(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	rec := httptest.NewRecorder()
	newServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		quick("/api/search?q=un+parser+yaml"), nil))
	if f.calls != 1 {
		t.Errorf("appels = %d, want 1 en mode rapide", f.calls)
	}
}

func TestVersionEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if !strings.Contains(rec.Body.String(), "test") {
		t.Errorf("version absente: %s", rec.Body.String())
	}
}
