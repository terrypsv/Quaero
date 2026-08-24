// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testClient(handler http.HandlerFunc) (*Client, *httptest.Server) {
	srv := httptest.NewServer(handler)
	return &Client{HTTP: srv.Client(), Token: "jeton-de-test", BaseURL: srv.URL}, srv
}

func TestSearchDecodesRepositories(t *testing.T) {
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer jeton-de-test" {
			t.Errorf("en-tete d'authentification = %q", got)
		}
		if q := r.URL.Query().Get("q"); q != "yaml language:Go" {
			t.Errorf("requete transmise = %q", q)
		}
		w.Header().Set("X-RateLimit-Remaining", "4990")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		_, _ = w.Write([]byte(`{
			"total_count": 1,
			"items": [{
				"full_name": "go-yaml/yaml",
				"name": "yaml",
				"html_url": "https://github.com/go-yaml/yaml",
				"description": "YAML support for Go",
				"language": "Go",
				"topics": ["yaml", "go"],
				"stargazers_count": 5000,
				"forks_count": 900,
				"open_issues_count": 120,
				"archived": false,
				"fork": false,
				"created_at": "2014-01-01T00:00:00Z",
				"pushed_at": "2026-08-01T00:00:00Z",
				"owner": {"login": "go-yaml"},
				"license": {"spdx_id": "MIT"}
			}]
		}`))
	})
	defer srv.Close()

	repos, total, rate, err := c.Search(context.Background(), "yaml language:Go", 30, 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 1 || len(repos) != 1 {
		t.Fatalf("total=%d repos=%d", total, len(repos))
	}

	r := repos[0]
	if r.FullName != "go-yaml/yaml" || r.Owner != "go-yaml" || r.License != "MIT" {
		t.Errorf("depot mal normalise: %+v", r)
	}
	if r.PushedAt.Year() != 2026 {
		t.Errorf("date d'envoi mal lue: %v", r.PushedAt)
	}
	if rate.Remaining != 4990 || rate.Limit != 5000 {
		t.Errorf("quota mal lu: %+v", rate)
	}
}

// Un message d'erreur doit dire quoi faire, pas seulement que ca a echoue.
func TestErrorMessagesAreActionable(t *testing.T) {
	cases := []struct {
		status int
		body   string
		expect string
	}{
		{http.StatusUnauthorized, `{"message":"Bad credentials"}`, "jeton"},
		{http.StatusUnprocessableEntity, `{"message":"Validation Failed"}`, "requete refusee"},
	}
	for _, tc := range cases {
		c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})
		_, _, _, err := c.Search(context.Background(), "x", 10, 1)
		srv.Close()

		if err == nil {
			t.Fatalf("statut %d: erreur attendue", tc.status)
		}
		if !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("message %q ne contient pas %q", err.Error(), tc.expect)
		}
	}
}

func TestExhaustedQuotaSaysWhenItResets(t *testing.T) {
	reset := time.Now().Add(42 * time.Minute)
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
	})
	defer srv.Close()

	_, _, _, err := c.Search(context.Background(), "x", 10, 1)
	if err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("erreur = %v, want une mention du quota", err)
	}
	if !strings.Contains(err.Error(), reset.Local().Format("15:04")) {
		t.Errorf("l'heure de reinitialisation manque: %v", err)
	}
}

func TestLimitIsCappedAtHundred(t *testing.T) {
	// Demander plus que le maximum renverrait silencieusement moins: on borne
	// plutot que de laisser croire a une page de mille resultats.
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q, want 100", got)
		}
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	})
	defer srv.Close()

	_, _, _, _ = c.Search(context.Background(), "x", 5000, 1)
}

func TestPageIsForwarded(t *testing.T) {
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("page"); got != "4" {
			t.Errorf("page = %q, want 4", got)
		}
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	})
	defer srv.Close()
	_, _, _, _ = c.Search(context.Background(), "x", 50, 4)
}

// Au-dela du millieme resultat l'API renvoie une erreur plutot qu'une page
// vide: on borne la demande au lieu de l'envoyer echouer.
func TestPageIsClampedAtTheApiCeiling(t *testing.T) {
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page > 20 {
			t.Errorf("page = %d, la borne de 1000 resultats n'a pas ete appliquee", page)
		}
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	})
	defer srv.Close()
	_, _, _, _ = c.Search(context.Background(), "x", 50, 999)
}

func TestMaxReachable(t *testing.T) {
	if got := MaxReachable(11000); got != 1000 {
		t.Errorf("MaxReachable(11000) = %d, want 1000", got)
	}
	if got := MaxReachable(42); got != 42 {
		t.Errorf("MaxReachable(42) = %d, want 42", got)
	}
}

func TestUnreadableBodyIsReported(t *testing.T) {
	c, srv := testClient(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{ ceci n est pas du json`))
	})
	defer srv.Close()

	if _, _, _, err := c.Search(context.Background(), "x", 10, 1); err == nil {
		t.Error("une reponse illisible doit remonter une erreur")
	}
}
