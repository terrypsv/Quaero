// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package webui serves the search interface and the JSON endpoint behind it.
//
// The whole binary is one file with the page embedded, deliberately. A search
// tool that needs a build step, a package manager and a reverse proxy before
// it answers a question is a tool nobody launches when they have a question.
package webui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/intent"
	"github.com/terrypsv/Quaero/internal/model"
	"github.com/terrypsv/Quaero/internal/rank"
	"github.com/terrypsv/Quaero/internal/reports"
)

//go:embed index.html
var indexHTML []byte

// fontFiles porte les polices de l'interface, produites par scripts/polices.py
// et livrees avec leur licence. Elles sont dans le binaire parce que la
// politique de contenu n'autorise aucune ressource exterieure.
//
//go:embed fonts
var fontFiles embed.FS

// Search scopes. English-only is the default because widening costs one API
// call per language variant, and making that automatic would quietly multiply
// everyone's quota consumption.
// French searches the words as typed, for projects described in French.
const (
	scopeEnglish = "anglais"
	scopeFrench  = "francais"
	scopeWide    = "elargi"
)

// pageSize is the number of repositories asked of GitHub per formulation and
// per page, the most the API hands out at once.
const pageSize = 100

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

// QuotaReader is implemented by a client that can read the search budget
// without spending it. The page asks for it on load, before any search, so
// that the budget is visible before it is used.
type QuotaReader interface {
	SearchQuota(ctx context.Context) (github.RateLimit, error)
}

// Server holds the dependencies of the HTTP layer.
type Server struct {
	Client  Searcher
	Version string
	// Addr est l'adresse d'ecoute, d'ou derivent les en-tetes Host acceptes.
	Addr string
	// Token est le jeton de session de cette execution (voir guard.go). Vide,
	// l'interface refuse tout.
	Token string
	// Scan analyse un depot depuis l'onglet audit (voir scan.go). Nil, l'onglet
	// dit que l'analyse n'est pas disponible.
	Scan ScanFunc
	// ScanTimeout est le delai accorde a chaque moteur d'une analyse, affiche
	// dans l'onglet audit. Zero, la page ne l'affiche pas.
	ScanTimeout time.Duration
	// Reports garde les rapports d'analyse que l'utilisateur enregistre (voir
	// reports.go). Nil, la page ne propose ni de les enregistrer ni de les
	// rouvrir.
	Reports *reports.Store

	cache     *searchCache
	scans     *scanJobs
	importing atomic.Bool
}

// Pages are kept ten minutes: long enough to re-sort, page back and forth or
// remove a filter for free, short enough that a fresh question sees fresh
// results.
const (
	cacheTTL   = 10 * time.Minute
	cachePages = 256
)

// Handler wires the routes behind the host guard: no route is reachable with
// a Host that does not designate this machine.
func (s *Server) Handler() http.Handler {
	if s.cache == nil {
		s.cache = newSearchCache(cacheTTL, cachePages)
	}
	if s.scans == nil {
		s.scans = &scanJobs{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/search", s.handleSearch)
	mux.HandleFunc("/api/read", s.handleRead)
	mux.HandleFunc("/api/quota", s.handleQuota)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/scan/cancel", s.handleScanCancel)
	mux.HandleFunc("/api/scan/advisory", s.handleScanAdvisory)
	mux.HandleFunc("/api/scan/save", s.handleScanSave)
	mux.HandleFunc("/api/reports", s.handleReports)
	mux.HandleFunc("/api/reports/view", s.handleReportView)
	mux.HandleFunc("/api/reports/import", s.handleReportImport)
	mux.HandleFunc("/api/reports/delete", s.handleReportDelete)
	mux.HandleFunc("/fonts/", s.handleFont)
	return guard{token: s.Token, allowed: allowedHosts(s.Addr), next: mux}
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
	// La page est embarquee dans le binaire (go:embed): aucune donnee venue de
	// l'exterieur n'y passe, il n'y a rien a echapper.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(indexHTML)
}

// handleFont sert une police embarquee, et rien d'autre: un nom sans dossier,
// en .woff2, present dans le binaire. Le reste du dossier (licences, sommes de
// controle) n'est pas servi.
func (s *Server) handleFont(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/fonts/")
	if name == "" || name != path.Base(name) || !strings.HasSuffix(name, ".woff2") {
		http.NotFound(w, r)
		return
	}
	data, err := fontFiles.ReadFile("fonts/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	// Une police ne change qu'avec le binaire: la garder un jour evite de la
	// recharger a chaque recherche.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.Version})
}

// handleQuota reports the search budget. It asks GitHub when the client can
// read it for free, and falls back to the last budget a search reported.
// A zero limit means the budget is unknown, and the page shows nothing.
func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	rate := s.cache.current()
	if reader, ok := s.Client.(QuotaReader); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if fresh, err := reader.SearchQuota(ctx); err == nil && fresh.Limit > 0 {
			s.cache.setRate(fresh)
			rate = fresh
		}
	}
	writeJSON(w, http.StatusOK, s.quota(rate))
}

// quota dit le budget a la page, et si Quaero cherche sans jeton.
func (s *Server) quota(rate github.RateLimit) model.Quota {
	q := quotaOf(rate, time.Now())
	if a, ok := s.Client.(interface{ Anonymous() bool }); ok && a.Anonymous() {
		q.Anonymous = true
	}
	return q
}

// quotaOf turns a rate limit into what the page displays.
func quotaOf(rate github.RateLimit, now time.Time) model.Quota {
	if rate.Limit <= 0 || rate.Remaining < 0 {
		return model.Quota{}
	}
	q := model.Quota{Remaining: rate.Remaining, Limit: rate.Limit}
	if !rate.ResetAt.IsZero() {
		q.ResetAt = rate.ResetAt.Local().Format("15:04:05")
		if d := rate.ResetAt.Sub(now); d > 0 {
			q.ResetIn = int(math.Ceil(d.Seconds()))
		}
	}
	return q
}

// handleRead returns how a phrase is read, without asking GitHub anything.
// The page calls it while the phrase is being typed, so that what will be
// searched is visible before a single request of the quota is spent.
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	phrase := r.URL.Query().Get("q")
	if strings.TrimSpace(phrase) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parametre q manquant"})
		return
	}
	in := intent.Read(phrase)
	if r.URL.Query().Get("scope") == scopeFrench {
		in = intent.French(in)
	}
	writeJSON(w, http.StatusOK, map[string]any{"intent": in, "query": intent.Query(in)})
}

var (
	// GitHub topics: lowercase letters, digits and hyphens, fifty at most.
	topicRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)
	// GitHub license keys: mit, apache-2.0, bsd-3-clause...
	licenseRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,30}$`)
	// GitHub logins: letters, digits and single hyphens, 39 at most.
	ownerRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	// GitHub language names: letters, digits, and the few signs real names
	// carry (C++, C#, Objective-C, Ren'Py, Jupyter Notebook).
	languageRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} +#.'-]{0,39}$`)
)

// maxFilterTopics bounds the topics a page can add. GitHub rejects queries
// past 256 characters, and three topics on top of the terms already make a
// very narrow question.
const maxFilterTopics = 3

// readFilters takes the criteria added by clicking on a page of results. Each
// value ends up inside a GitHub qualifier, so a value that could close the
// qualifier and open another one (a colon, a quote) is refused, not escaped.
func readFilters(v url.Values) model.Filters {
	var f model.Filters
	if lang := strings.TrimSpace(v.Get("lang")); languageRe.MatchString(lang) {
		f.Language = lang
	}
	for _, raw := range v["topic"] {
		t := strings.ToLower(strings.TrimSpace(raw))
		if topicRe.MatchString(t) && len(f.Topics) < maxFilterTopics && !slices.Contains(f.Topics, t) {
			f.Topics = append(f.Topics, t)
		}
	}
	if n, err := strconv.Atoi(v.Get("stars")); err == nil && n > 0 && n <= 1000000 {
		f.MinStars = n
	}
	if n, err := strconv.Atoi(v.Get("days")); err == nil && n > 0 && n <= 3650 {
		f.PushedWithinDays = n
	}
	// "noassertion" et "other" sont ce que GitHub renvoie pour une licence
	// qu'il ne reconnait pas: ce ne sont pas des cles cherchables.
	if lic := strings.ToLower(strings.TrimSpace(v.Get("license"))); licenseRe.MatchString(lic) && lic != "noassertion" && lic != "other" {
		f.License = lic
	}
	if owner := strings.TrimSpace(v.Get("owner")); ownerRe.MatchString(owner) {
		f.Owner = owner
	}
	f.NoLists = v.Get("nolists") == "1"
	return f
}

// isList reports whether a repository is an "awesome" list: a page of links
// to tools rather than a tool.
func isList(r model.Repo) bool {
	if strings.HasPrefix(strings.ToLower(r.Name), "awesome") {
		return true
	}
	for _, t := range r.Topics {
		if t == "awesome" || t == "awesome-list" || t == "awesome-lists" {
			return true
		}
	}
	return false
}

// keep removes what the phrase or the filters asked to keep out. GitHub
// applies NOT to the queries that carry words, but the topic strategy has
// none, and a list can be named "awesome" without saying so in its topics.
// Checking the merged results here makes the exclusion hold whatever query
// found the repository.
func keep(repos []model.Repo, in model.Intent) []model.Repo {
	if len(in.Exclude) == 0 && !in.Filters.NoLists {
		return repos
	}
	out := make([]model.Repo, 0, len(repos))
	for _, r := range repos {
		if in.Filters.NoLists && isList(r) {
			continue
		}
		if mentions(r, in.Exclude) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// mentions reports whether a repository carries one of the words, in its
// name, description or topics, the fields GitHub searches by default. Whole
// words only, as GitHub matches them: excluding "go" must not exclude
// "google". Hyphens and spaces are treated alike, "active-directory" matches
// "Active Directory".
func mentions(r model.Repo, words []string) bool {
	if len(words) == 0 {
		return false
	}
	hay := flatWords(r.Name + " " + r.Description + " " + strings.Join(r.Topics, " "))
	for _, w := range words {
		if w = flatWords(w); w != "  " && strings.Contains(hay, w) {
			return true
		}
	}
	return false
}

// flatWords lowercases s and keeps its words, separated and surrounded by
// single spaces, so that a word can be looked for with its boundaries.
func flatWords(s string) string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '+' && r != '#'
	})
	return " " + strings.Join(fields, " ") + " "
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	phrase := r.URL.Query().Get("q")
	if phrase == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "parametre q manquant",
		})
		return
	}

	// Cent depots par formulation: c'est le maximum d'une page GitHub, et il
	// coute la meme requete que cinquante. La page affiche ensuite ce qu'on
	// lui demande (5, 20, 50, 100 ou tout), sans rien redemander.
	limit := pageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < limit {
			limit = n
		}
	}

	// upto dit combien de pages GitHub de chaque formulation sont fusionnees.
	// "Charger la suite" demande une page de plus, les precedentes reviennent
	// du cache, et toute la liste est classee d'un seul tenant.
	upto := 1
	if raw := r.URL.Query().Get("upto"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			upto = n
		}
	}
	if most := github.MaxReachable(math.MaxInt32) / limit; upto > most {
		upto = most
	}

	mode := r.URL.Query().Get("sort")
	if mode == "" {
		mode = rank.SortRelevance
	}

	scope := r.URL.Query().Get("scope")
	if scope != scopeWide && scope != scopeFrench {
		scope = scopeEnglish
	}

	precision := r.URL.Query().Get("precision")
	if precision != precisionQuick {
		precision = precisionDeep
	}

	started := time.Now()
	in := intent.Read(phrase)
	if scope == scopeFrench {
		in = intent.French(in)
	}
	in.Filters = readFilters(r.URL.Query())
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

	failed := false
	for _, st := range strategies {
		for p := 1; p <= upto; p++ {
			stRepos, stTotal, stRate, stErr := s.cache.search(ctx, s.Client, st.Query, limit, p)
			rate = stRate
			if stErr != nil {
				// The first failure is fatal; a later one just stops the
				// search, because partial results are still results.
				if len(queries) == 0 {
					err = stErr
				}
				failed = true
				break
			}
			if p == 1 {
				queries = append(queries, st.Query)
			}
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
				if p == 1 || !slices.Contains(existing.FoundBy, st.Label) {
					existing.FoundBy = append(existing.FoundBy, st.Label)
					existing.Agreement += st.Weight
				}
			}
			// Une page incomplete est la derniere: en demander une autre
			// couterait une requete pour rien.
			if len(stRepos) < limit || p*limit >= github.MaxReachable(stTotal) {
				break
			}
		}
		if failed {
			break
		}
	}

	repos := make([]model.Repo, 0, len(order))
	for _, key := range order {
		repos = append(repos, *merged[key])
	}
	repos = keep(repos, in)

	// Widening runs the same search with the head term written as other
	// communities write it. A very large part of GitHub is described in
	// Chinese, and a meaningful body of work in Russian, Japanese and Spanish;
	// an English-only search excludes all of it without ever saying so.
	if err == nil && scope == scopeWide {
		seen := map[string]bool{}
		for _, r := range repos {
			seen[r.FullName] = true
		}
		// Six variantes au plus: le francais d'abord, puis les communautes les
		// plus presentes sur GitHub.
		for _, alt := range intent.Widen(in, 6) {
			altRepos, altTotal, altRate, altErr := s.cache.search(ctx, s.Client, alt, limit, 1)
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
		repos = keep(repos, in)
	}

	// Une page vide est la pire reponse possible: elle ne distingue pas
	// "n'existe pas" de "requete trop serree". On desserre alors les
	// contraintes une a une, et on dit lesquelles.
	var relaxed []string
	if err == nil && len(repos) == 0 && upto == 1 {
		for _, step := range intent.Ladder(in) {
			stepRepos, stepTotal, stepRate, stepErr := s.cache.search(ctx, s.Client, step.Query, limit, 1)
			rate = stepRate
			if stepErr != nil {
				break
			}
			relaxed = append(relaxed, step.Reason)
			if stepTotal > 0 {
				repos, total, query, in = keep(stepRepos, step.Intent), stepTotal, step.Query, step.Intent
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
		Page:      upto,
		Pages:     pages,
		NextCost:  len(strategies),
		Reachable: reachable,
		Sort:      mode,
		Scope:     scope,
		Queries:   queries,
		Precision: precision,
	}

	// The budget left is always reported, the page keeps it in view. The gap
	// between matches and reachable results is explained by the page too,
	// next to the criteria that close it.
	result.Quota = s.quota(rate)

	if len(relaxed) > 0 && total > 0 {
		result.Note = intent.Describe(relaxed)
	}

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
