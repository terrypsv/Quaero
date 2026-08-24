// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package model holds the shapes Quaero passes between its layers: what a
// repository looks like once normalised, and what a search intent looks like
// once a phrase has been read.
package model

import "time"

// Repo is a repository reduced to what actually helps a decision.
//
// GitHub returns dozens of fields; most answer questions nobody asks. The ones
// kept here answer two: does this do what I need, and can I depend on it. The
// second question is the one the native interface buries, which is why it gets
// as much room as the first.
type Repo struct {
	FullName    string    `json:"full_name"`
	Owner       string    `json:"owner"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Language    string    `json:"language"`
	Topics      []string  `json:"topics"`
	Stars       int       `json:"stars"`
	Forks       int       `json:"forks"`
	OpenIssues  int       `json:"open_issues"`
	License     string    `json:"license"`
	Archived    bool      `json:"archived"`
	Fork        bool      `json:"fork"`
	CreatedAt   time.Time `json:"created_at"`
	PushedAt    time.Time `json:"pushed_at"`

	// Script is the dominant writing system of the description, filled by the
	// ranking layer. GitHub records no country, so this is the closest signal
	// available for separating linguistic communities.
	Script string `json:"script,omitempty"`
	// Health is filled by the ranking layer, not by the API.
	Health Health `json:"health"`
	// Score is the relevance score for the current query.
	Score float64 `json:"score"`
	// Why explains, in one line, what earned this position. A ranking nobody
	// can question is a ranking nobody can trust.
	Why []string `json:"why,omitempty"`
	// FoundBy names the strategies that returned this repository. Agreement
	// between independent ways of asking is the strongest relevance signal
	// available, and it is only visible when the provenance is kept.
	FoundBy []string `json:"found_by,omitempty"`
	// Agreement is the summed weight of the strategies that found it.
	Agreement float64 `json:"agreement,omitempty"`
}

// Health rates whether a repository can be depended upon.
//
// The signals are deliberately blunt and explainable. A composite number that
// nobody can decompose would be worse than no number at all: the reader could
// not tell a dormant-but-finished library from an abandoned one.
type Health struct {
	// Level is one of: sain, calme, dormant, abandonne, archive.
	Level string `json:"level"`
	// DaysSincePush is the age of the last push, in days.
	DaysSincePush int `json:"days_since_push"`
	// IssueRatio is open issues per hundred stars, a rough measure of whether
	// maintenance keeps up with use. Zero when the repo has no stars.
	IssueRatio float64 `json:"issue_ratio"`
	// Notes carry the human-readable reasons behind Level.
	Notes []string `json:"notes,omitempty"`
}

// Intent is a search phrase after it has been read.
//
// The whole point of Quaero is that a person types what they want, not the
// query syntax that would find it. Intent is the bridge: the phrase becomes
// terms plus facets, and the facets become API qualifiers.
type Intent struct {
	// Raw is the phrase as typed.
	Raw string `json:"raw"`
	// Terms are the content words that survive after stop words and facet
	// phrases have been removed.
	Terms []string `json:"terms"`
	// Language, when the phrase named one.
	Language string `json:"language"`
	// Topics extracted from the phrase.
	Topics []string `json:"topics"`
	// MinStars, when the phrase asked for popularity.
	MinStars int `json:"min_stars"`
	// PushedWithinDays, when the phrase asked for recency.
	PushedWithinDays int `json:"pushed_within_days"`
	// ExcludeForks and ExcludeArchived are on by default; a phrase can turn
	// them off explicitly.
	ExcludeForks    bool `json:"exclude_forks"`
	ExcludeArchived bool `json:"exclude_archived"`
	// Explain lists the facets that were understood, so the user can see how
	// their sentence was read and correct it if it was read wrong.
	Explain []string `json:"explain,omitempty"`
}

// Result is what the web layer renders.
type Result struct {
	Intent  Intent `json:"intent"`
	Query   string `json:"query"`
	Repos   []Repo `json:"repos"`
	Total   int    `json:"total"`
	Elapsed string `json:"elapsed"`
	Note    string `json:"note,omitempty"`

	// Page is the 1-based page shown.
	Page int `json:"page"`
	// Pages is how many pages can actually be reached. GitHub stops handing
	// out results at a thousand, so a search matching eleven thousand
	// repositories still only offers ten pages. Reporting the match count as
	// if it were reachable would promise pages that come back empty.
	Pages int `json:"pages"`
	// Reachable is the number of results that can actually be paged through.
	Reachable int `json:"reachable"`
	// Sort is the ordering applied.
	Sort string `json:"sort"`

	// Quota is what the API budget looks like after this search. Showing it
	// permanently rather than only when it runs out means a user who is about
	// to be cut off can see it coming.
	Quota Quota `json:"quota"`

	// Scope is "anglais" or "elargi".
	Scope string `json:"scope"`
	// Queries lists every query actually sent, so a widened search remains
	// as inspectable as a simple one.
	Queries []string `json:"queries,omitempty"`
	// Precision is "rapide" or "approfondie".
	Precision string `json:"precision"`
}

// Quota mirrors the API rate limit for display.
type Quota struct {
	Remaining int    `json:"remaining"`
	Limit     int    `json:"limit"`
	ResetAt   string `json:"reset_at,omitempty"`
}
