// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package github talks to the repository search API.
//
// The client is deliberately thin. It authenticates, asks, decodes, and
// surfaces rate-limit state; it makes no judgement about the results. Ranking
// belongs to a separate package because ranking is opinion, and opinion should
// be testable without a network.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/model"
)

const (
	apiBase = "https://api.github.com"
	// GitHub caps repository search at 100 results per page and 1000 overall.
	// Asking for more silently returns less, so the limits are stated here
	// rather than discovered in production. A search reporting eleven thousand
	// matches will still only ever hand over a thousand of them; pretending
	// otherwise would promise pages that come back empty.
	maxPerPage = 100
	maxResults = 1000
)

// ErrNoToken is returned when no credential is available.
//
// Anonymous access is capped at 60 requests per hour, which a single search
// session exhausts. Rather than half-work and fail confusingly on the fifth
// query, the client refuses to start without a token.
var ErrNoToken = fmt.Errorf("aucun jeton GitHub: definir GITHUB_TOKEN ou GH_TOKEN")

// Client queries the GitHub search API.
type Client struct {
	HTTP    *http.Client
	Token   string
	BaseURL string
}

// RateLimit is what the API says about the budget left.
type RateLimit struct {
	Remaining int
	Limit     int
	ResetAt   time.Time
}

// New builds a client from the environment, falling back to the stored token.
//
// The environment wins over the file so that a one-off run with a different
// credential does not require editing configuration. Two variable names are
// accepted because gh writes GH_TOKEN and most CI systems write GITHUB_TOKEN;
// requiring one specific name would be a trap for whoever already has the
// other set.
func New() (*Client, error) {
	token := firstNonEmpty(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN"), LoadToken())
	if token == "" {
		return nil, ErrNoToken
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 20 * time.Second},
		Token:   token,
		BaseURL: apiBase,
	}, nil
}

type searchResponse struct {
	TotalCount        int           `json:"total_count"`
	IncompleteResults bool          `json:"incomplete_results"`
	Items             []repoItem    `json:"items"`
	Message           string        `json:"message"`
	Errors            []apiSubError `json:"errors"`
}

type apiSubError struct {
	Message string `json:"message"`
}

type repoItem struct {
	FullName    string   `json:"full_name"`
	Name        string   `json:"name"`
	HTMLURL     string   `json:"html_url"`
	Description string   `json:"description"`
	Language    string   `json:"language"`
	Topics      []string `json:"topics"`
	Stars       int      `json:"stargazers_count"`
	Forks       int      `json:"forks_count"`
	OpenIssues  int      `json:"open_issues_count"`
	Archived    bool     `json:"archived"`
	Fork        bool     `json:"fork"`
	CreatedAt   string   `json:"created_at"`
	PushedAt    string   `json:"pushed_at"`
	Owner       struct {
		Login string `json:"login"`
	} `json:"owner"`
	License struct {
		SPDX string `json:"spdx_id"`
	} `json:"license"`
}

// MaxReachable reports how many results can actually be paged through for a
// given total. The API stops at a thousand whatever the match count.
func MaxReachable(total int) int {
	if total > maxResults {
		return maxResults
	}
	return total
}

// Search runs one repository search page and returns normalised repositories.
//
// The sort is left to GitHub's own relevance ("best match") on purpose: it is
// a reasonable first pass over an index Quaero does not hold. The reordering
// that follows is where Quaero's opinion is applied.
func (c *Client) Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, RateLimit, error) {
	if limit <= 0 || limit > maxPerPage {
		limit = maxPerPage
	}
	if page < 1 {
		page = 1
	}
	// Beyond the thousandth result the API returns an error rather than an
	// empty page, so the request is clamped instead of being sent to fail.
	if page*limit > maxResults {
		page = maxResults / limit
		if page < 1 {
			page = 1
		}
	}

	endpoint := c.BaseURL + "/search/repositories?" + url.Values{
		"q":        {query},
		"per_page": {strconv.Itoa(limit)},
		"page":     {strconv.Itoa(page)},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, RateLimit{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "quaero")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, RateLimit{}, fmt.Errorf("appel GitHub: %w", err)
	}
	defer resp.Body.Close()

	rate := readRate(resp.Header)

	var payload searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, 0, rate, fmt.Errorf("reponse GitHub illisible: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, rate, apiError(resp.StatusCode, payload, rate)
	}

	repos := make([]model.Repo, 0, len(payload.Items))
	for _, item := range payload.Items {
		repos = append(repos, normalise(item))
	}
	return repos, payload.TotalCount, rate, nil
}

// apiError turns an HTTP failure into a message that says what to do next.
func apiError(status int, payload searchResponse, rate RateLimit) error {
	detail := payload.Message
	for _, e := range payload.Errors {
		if e.Message != "" {
			detail += "; " + e.Message
		}
	}
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("jeton GitHub refuse: verifier GITHUB_TOKEN (%s)", detail)
	case http.StatusForbidden:
		if rate.Remaining == 0 {
			return fmt.Errorf("quota GitHub epuise, reinitialisation a %s",
				rate.ResetAt.Local().Format("15:04:05"))
		}
		return fmt.Errorf("acces refuse par GitHub: %s", detail)
	case http.StatusUnprocessableEntity:
		// The usual cause is a query that is syntactically impossible, which
		// means the phrase was read into something GitHub cannot express.
		return fmt.Errorf("requete refusee par GitHub, la phrase a produit une requete invalide: %s", detail)
	default:
		return fmt.Errorf("GitHub a repondu %d: %s", status, detail)
	}
}

func normalise(item repoItem) model.Repo {
	return model.Repo{
		FullName:    item.FullName,
		Owner:       item.Owner.Login,
		Name:        item.Name,
		Description: item.Description,
		URL:         item.HTMLURL,
		Language:    item.Language,
		Topics:      item.Topics,
		Stars:       item.Stars,
		Forks:       item.Forks,
		OpenIssues:  item.OpenIssues,
		License:     item.License.SPDX,
		Archived:    item.Archived,
		Fork:        item.Fork,
		CreatedAt:   parseTime(item.CreatedAt),
		PushedAt:    parseTime(item.PushedAt),
	}
}

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

func readRate(h http.Header) RateLimit {
	rate := RateLimit{
		Remaining: atoiOr(h.Get("X-RateLimit-Remaining"), -1),
		Limit:     atoiOr(h.Get("X-RateLimit-Limit"), -1),
	}
	if sec := atoiOr(h.Get("X-RateLimit-Reset"), 0); sec > 0 {
		rate.ResetAt = time.Unix(int64(sec), 0)
	}
	return rate
}

func atoiOr(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
