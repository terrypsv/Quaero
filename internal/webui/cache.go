// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/model"
)

// searchCache keeps the pages GitHub returned for a few minutes, and the last
// budget it reported.
//
// Repository search allows thirty calls a minute and a deep search spends
// five. Changing the sort order, coming back to a page or toggling a filter
// off used to repeat every one of those calls, although the ranking happens
// here and not at GitHub. Serving the same page again from memory is what
// keeps the budget for new questions.
type searchCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]cachedPage
	rate    github.RateLimit
}

type cachedPage struct {
	repos []model.Repo
	total int
	at    time.Time
}

func newSearchCache(ttl time.Duration, max int) *searchCache {
	return &searchCache{ttl: ttl, max: max, now: time.Now, entries: map[string]cachedPage{}}
}

// search answers from memory when the same page was fetched recently, and
// asks GitHub otherwise. Failures are not kept: the next attempt asks again.
func (c *searchCache) search(ctx context.Context, client Searcher, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error) {
	key := query + "\x00" + strconv.Itoa(limit) + "\x00" + strconv.Itoa(page)

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Sub(e.at) < c.ttl {
		repos := append([]model.Repo(nil), e.repos...)
		rate := c.currentLocked()
		c.mu.Unlock()
		return repos, e.total, rate, nil
	}
	c.mu.Unlock()

	repos, total, rate, err := client.Search(ctx, query, limit, page)

	c.mu.Lock()
	defer c.mu.Unlock()
	if rate.Limit > 0 {
		c.rate = rate
	}
	if err != nil {
		return repos, total, rate, err
	}
	c.storeLocked(key, repos, total)
	return repos, total, rate, nil
}

// current returns the last budget GitHub reported, full again if its reset
// time has passed: the search budget refills completely every minute.
func (c *searchCache) current() github.RateLimit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentLocked()
}

func (c *searchCache) currentLocked() github.RateLimit {
	r := c.rate
	if r.Limit > 0 && !r.ResetAt.IsZero() && !c.now().Before(r.ResetAt) {
		r.Remaining = r.Limit
		r.ResetAt = time.Time{}
	}
	return r
}

// setRate records a budget read without searching.
func (c *searchCache) setRate(rate github.RateLimit) {
	if rate.Limit <= 0 {
		return
	}
	c.mu.Lock()
	c.rate = rate
	c.mu.Unlock()
}

func (c *searchCache) storeLocked(key string, repos []model.Repo, total int) {
	now := c.now()
	for k, e := range c.entries {
		if now.Sub(e.at) >= c.ttl {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.max {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.at.Before(oldest) {
				oldestKey, oldest = k, e.at
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = cachedPage{repos: append([]model.Repo(nil), repos...), total: total, at: now}
}
