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

func search(t *testing.T, h http.Handler, url string) model.Result {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: code %d, %s", url, rec.Code, rec.Body.String())
	}
	var out model.Result
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	return out
}

// Les criteres choisis parmi les resultats partent chez GitHub, et la reponse
// les renvoie pour que la page les affiche et permette de les retirer.
func TestFiltresTransmis(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	out := search(t, newServer(f), quick("/api/search?q=pot+de+miel+ssh&lang=Python&topic=threat-intelligence&topic=telnet&stars=100&days=90"))

	for _, want := range []string{"honeypot", "language:Python", "topic:threat-intelligence", "topic:telnet", "stars:>=100", "pushed:>="} {
		if !strings.Contains(f.lastQuery, want) {
			t.Errorf("requete %q sans %s", f.lastQuery, want)
		}
	}
	got := out.Intent.Filters
	if got.Language != "Python" || len(got.Topics) != 2 || got.MinStars != 100 || got.PushedWithinDays != 90 {
		t.Errorf("filtres renvoyes = %+v", got)
	}
}

// Une valeur qui fermerait le qualificatif pour en ouvrir un autre est
// refusee, pas echappee.
func TestFiltresInvalidesIgnores(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	out := search(t, newServer(f), quick(`/api/search?q=yaml&lang=Go+stars:>1&topic=a:b&topic=%22x%22&topic=Bad+Topic&stars=-5&days=99999`))

	for _, bad := range []string{"stars:>1", "a:b", `"x"`, "Bad", "stars:>=-5"} {
		if strings.Contains(f.lastQuery, bad) {
			t.Errorf("requete %q contient %s", f.lastQuery, bad)
		}
	}
	if got := out.Intent.Filters; got.Language != "" || len(got.Topics) != 0 || got.MinStars != 0 || got.PushedWithinDays != 0 {
		t.Errorf("filtres invalides acceptes: %+v", got)
	}
}

func TestTroisSujetsAuPlus(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	out := search(t, newServer(f), quick("/api/search?q=yaml&topic=a1&topic=b2&topic=c3&topic=d4&topic=a1"))
	if n := len(out.Intent.Filters.Topics); n != maxFilterTopics {
		t.Errorf("%d sujets gardes, attendu %d", n, maxFilterTopics)
	}
}

// Changer de tri ne repose pas la question a GitHub: le classement se fait ici.
func TestCacheEpargneLeQuota(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/yaml", Name: "yaml", Stars: 10, PushedAt: time.Now()}}}
	h := newServer(f)

	search(t, h, "/api/search?q=parser+yaml")
	first := f.calls
	if first < 2 {
		t.Fatalf("recherche approfondie en %d appel(s)", first)
	}
	search(t, h, "/api/search?q=parser+yaml&sort=populaire")
	if f.calls != first {
		t.Errorf("changer de tri a coute %d appel(s)", f.calls-first)
	}
	// Une page complete appelle la suivante: "charger la suite" la demande,
	// et seulement elle.
	f.repos = make([]model.Repo, pageSize)
	for i := range f.repos {
		f.repos[i] = model.Repo{FullName: fmt.Sprintf("a/r%d", i), Name: fmt.Sprintf("r%d", i)}
	}
	f.total = 5000
	h = newServer(f)
	search(t, h, "/api/search?q=parser+yaml")
	before := f.calls
	search(t, h, "/api/search?q=parser+yaml&upto=2")
	if f.calls == before {
		t.Error("la page suivante doit etre demandee a GitHub")
	}
}

// Un echec n'est pas garde: la tentative suivante redemande.
func TestCacheNeGardePasLesEchecs(t *testing.T) {
	f := &fakeSearcher{err: context.DeadlineExceeded}
	h := newServer(f)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, quick("/api/search?q=yaml"), nil))
	}
	if f.calls != 2 {
		t.Errorf("appels = %d, attendu 2", f.calls)
	}
}

type quotaSearcher struct {
	fakeSearcher
	quota github.RateLimit
	asked int
}

func (q *quotaSearcher) SearchQuota(ctx context.Context) (github.RateLimit, error) {
	q.asked++
	return q.quota, nil
}

func quotaOfServer(t *testing.T, h http.Handler) model.Quota {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/quota", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var q model.Quota
	if err := json.NewDecoder(rec.Body).Decode(&q); err != nil {
		t.Fatal(err)
	}
	return q
}

// Le quota s'affiche des l'ouverture, avant toute recherche.
func TestQuotaLuAuChargement(t *testing.T) {
	q := &quotaSearcher{quota: github.RateLimit{Remaining: 25, Limit: 30, ResetAt: time.Now().Add(42 * time.Second)}}
	got := quotaOfServer(t, newServer(q))
	if q.asked != 1 {
		t.Errorf("quota demande %d fois", q.asked)
	}
	if got.Remaining != 25 || got.Limit != 30 || got.ResetIn < 1 || got.ResetIn > 43 {
		t.Errorf("quota = %+v", got)
	}
}

// Sans lecture possible, le dernier quota vu dans une recherche fait foi; sans
// rien, la limite vaut zero et la page n'affiche rien.
func TestQuotaSansLecteur(t *testing.T) {
	f := &fakeSearcher{total: 1, repos: []model.Repo{{FullName: "a/b", Name: "b"}}}
	h := newServer(f)
	if got := quotaOfServer(t, h); got.Limit != 0 {
		t.Errorf("quota inconnu affiche: %+v", got)
	}
	f.rate = github.RateLimit{Remaining: 29, Limit: 30, ResetAt: time.Now().Add(time.Minute)}
	search(t, h, quick("/api/search?q=yaml"))
	if got := quotaOfServer(t, h); got.Remaining != 29 || got.Limit != 30 {
		t.Errorf("quota apres recherche = %+v", got)
	}
}

// Passe l'heure de reinitialisation, le quota de recherche est plein.
func TestQuotaPleinApresReinitialisation(t *testing.T) {
	c := newSearchCache(time.Minute, 4)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.setRate(github.RateLimit{Remaining: 2, Limit: 30, ResetAt: now.Add(10 * time.Second)})
	if got := c.current(); got.Remaining != 2 {
		t.Errorf("avant reinitialisation = %d", got.Remaining)
	}
	now = now.Add(11 * time.Second)
	if got := c.current(); got.Remaining != 30 || !got.ResetAt.IsZero() {
		t.Errorf("apres reinitialisation = %+v", got)
	}
}

// Le cache garde un nombre borne de pages et oublie les plus anciennes.
func TestCacheBorne(t *testing.T) {
	c := newSearchCache(time.Hour, 2)
	f := &fakeSearcher{total: 1}
	ctx := context.Background()
	for _, q := range []string{"a", "b", "c"} {
		_, _, _, _ = c.search(ctx, f, q, 50, 1)
	}
	if len(c.entries) != 2 {
		t.Errorf("%d pages gardees, attendu 2", len(c.entries))
	}
	_, _, _, _ = c.search(ctx, f, "c", 50, 1)
	if f.calls != 3 {
		t.Errorf("la page la plus recente devait etre servie de memoire, appels = %d", f.calls)
	}
}
