// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package webui serves the search interface and the JSON endpoint behind it.
//
// The whole binary is one file with the page embedded, deliberately. A search
// tool that needs a build step, a package manager and a reverse proxy before
// it answers a question is a tool nobody launches when they have a question.
package webui

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/intent"
	"github.com/terrypsv/Quaero/internal/model"
	"github.com/terrypsv/Quaero/internal/rank"
)

//go:embed index.html
var indexHTML []byte

// Search scopes. English-only is the default because widening costs one API
// call per language variant, and making that automatic would quietly multiply
// everyone's quota consumption.
const (
	scopeEnglish = "anglais"
	scopeWide    = "elargi"
)

// Precision modes. Deep is the default: the extra API calls buy agreement
// between independent formulations, which is the difference between a list
// that contains the answer somewhere and a list that starts with it.
const (
	precisionQuick = "rapide"
	precisionDeep  = "approfondie"
)

// Searcher is the part of the GitHub client this package needs. Narrowing it
// to one method keeps the handler testable without a network.
type Searcher interface {
	Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error)
}

// Server holds the dependencies of the HTTP layer.
type Server struct {
	Client  Searcher
	Version string
}

// Handler wires the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/search", s.handleSearch)
	mux.HandleFunc("/api/version", s.handleVersion)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page holds no secret and is served from memory; caching it would
	// only make a version change confusing during development.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.Version})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	phrase := r.URL.Query().Get("q")
	if phrase == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "parametre q manquant",
		})
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			page = n
		}
	}

	mode := r.URL.Query().Get("sort")
	if mode == "" {
		mode = rank.SortRelevance
	}

	scope := r.URL.Query().Get("scope")
	if scope != scopeWide {
		scope = scopeEnglish
	}

	precision := r.URL.Query().Get("precision")
	if precision != precisionQuick {
		precision = precisionDeep
	}

	started := time.Now()
	in := intent.Read(phrase)
	query := intent.Query(in)

	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()

	// Several formulations of the same question, merged. A repository returned
	// by more than one of them is far more likely to be the answer than one
	// that only surfaced in the general search, and that agreement cannot be
	// observed from a single result list.
	strategies := intent.Strategies(in, precision == precisionDeep)

	merged := map[string]*model.Repo{}
	var order []string
	var queries []string
	total := 0
	var rate github.RateLimit
	var err error

	for _, st := range strategies {
		stRepos, stTotal, stRate, stErr := s.Client.Search(ctx, st.Query, limit, page)
		rate = stRate
		if stErr != nil {
			// The first failure is fatal; a later one just stops the widening,
			// because partial results are still results.
			if len(queries) == 0 {
				err = stErr
				break
			}
			break
		}
		queries = append(queries, st.Query)
		if stTotal > total {
			total = stTotal
		}
		for i := range stRepos {
			key := stRepos[i].FullName
			existing, seen := merged[key]
			if !seen {
				copied := stRepos[i]
				copied.FoundBy = []string{st.Label}
				copied.Agreement = st.Weight
				merged[key] = &copied
				order = append(order, key)
				continue
			}
			existing.FoundBy = append(existing.FoundBy, st.Label)
			existing.Agreement += st.Weight
		}
	}

	repos := make([]model.Repo, 0, len(order))
	for _, key := range order {
		repos = append(repos, *merged[key])
	}

	// Widening runs the same search with the head term written as other
	// communities write it. A very large part of GitHub is described in
	// Chinese, and a meaningful body of work in Russian, Japanese and Spanish;
	// an English-only search excludes all of it without ever saying so.
	if err == nil && scope == scopeWide && page == 1 {
		seen := map[string]bool{}
		for _, r := range repos {
			seen[r.FullName] = true
		}
		for _, alt := range intent.Widen(in, 5) {
			altRepos, altTotal, altRate, altErr := s.Client.Search(ctx, alt, limit, 1)
			rate = altRate
			if altErr != nil {
				break
			}
			queries = append(queries, alt)
			total += altTotal
			for _, candidate := range altRepos {
				if seen[candidate.FullName] {
					continue
				}
				seen[candidate.FullName] = true
				candidate.FoundBy = []string{"autre langue"}
				candidate.Agreement = 1
				repos = append(repos, candidate)
			}
		}
	}

	// Une page vide est la pire reponse possible: elle ne distingue pas
	// "n'existe pas" de "requete trop serree". On desserre alors les
	// contraintes une a une, et on dit lesquelles.
	var relaxed []string
	if err == nil && len(repos) == 0 && page == 1 {
		for _, step := range intent.Ladder(in) {
			stepRepos, stepTotal, stepRate, stepErr := s.Client.Search(ctx, step.Query, limit, 1)
			rate = stepRate
			if stepErr != nil {
				break
			}
			relaxed = append(relaxed, step.Reason)
			if stepTotal > 0 {
				repos, total, query, in = stepRepos, stepTotal, step.Query, step.Intent
				queries = append(queries, step.Query)
				break
			}
		}
	}

	if err != nil {
		// The query that was actually sent is returned alongside the error.
		// Debugging a search you cannot see is guesswork, and the query is
		// exactly what the user needs to understand a surprising result.
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":  err.Error(),
			"query":  query,
			"intent": in,
		})
		return
	}

	reachable := github.MaxReachable(total)
	pages := reachable / limit
	if reachable%limit != 0 {
		pages++
	}

	result := model.Result{
		Intent:    in,
		Query:     query,
		Repos:     rank.Score(repos, in, mode),
		Total:     total,
		Elapsed:   time.Since(started).Round(time.Millisecond).String(),
		Page:      page,
		Pages:     pages,
		Reachable: reachable,
		Sort:      mode,
		Scope:     scope,
		Queries:   queries,
		Precision: precision,
	}

	if rate.Limit > 0 {
		result.Quota = model.Quota{Remaining: rate.Remaining, Limit: rate.Limit}
		if !rate.ResetAt.IsZero() {
			result.Quota.ResetAt = rate.ResetAt.Local().Format("15:04")
		}
	}

	if len(relaxed) > 0 && total > 0 {
		result.Note = intent.Describe(relaxed)
	}

	// GitHub hands out at most a thousand results whatever the match count.
	// Saying so is more useful than letting the user page into emptiness and
	// conclude the tool is broken.
	if total > reachable {
		result.Note = joinNotes(result.Note, fmt.Sprintf(
			"%d depots correspondent, mais l'API GitHub n'en restitue que %d. Affiner la phrase pour reduire le champ.",
			total, reachable))
	}

	// A quota that is about to run out changes what the user should do next,
	// so it is surfaced rather than discovered through a sudden failure.
	if rate.Remaining >= 0 && rate.Remaining < 10 {
		quota := fmt.Sprintf("quota GitHub bientot epuise: %d requete(s) restante(s), reinitialisation a %s",
			rate.Remaining, rate.ResetAt.Local().Format("15:04:05"))
		result.Note = joinNotes(result.Note, quota)
	}

	writeJSON(w, http.StatusOK, result)
}

// joinNotes concatenates messages with a separator, skipping the empties.
func joinNotes(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, strings.TrimSpace(p))
		}
	}
	return strings.Join(kept, " ")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
