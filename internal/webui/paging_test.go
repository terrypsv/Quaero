// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"fmt"
	"testing"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/model"
)

// pagedSearcher rend des depots differents a chaque page, comme GitHub, et
// une page incomplete quand le total est atteint.
type pagedSearcher struct {
	total    int
	calls    int
	lastPage int
}

func (p *pagedSearcher) Search(ctx context.Context, query string, limit, page int) ([]model.Repo, int, github.RateLimit, error) {
	p.calls++
	p.lastPage = page
	var out []model.Repo
	for i := (page - 1) * limit; i < page*limit && i < p.total; i++ {
		out = append(out, model.Repo{FullName: fmt.Sprintf("o/r%d", i), Name: fmt.Sprintf("r%d", i)})
	}
	return out, p.total, github.RateLimit{}, nil
}

// Cent depots par formulation: le maximum d'une page GitHub, pour le prix
// d'une seule requete.
func TestCentParFormulation(t *testing.T) {
	f := &pagedSearcher{total: 5000}
	out := search(t, newServer(f), quick("/api/search?q=yaml"))
	if len(out.Repos) != pageSize {
		t.Errorf("%d depots, attendu %d", len(out.Repos), pageSize)
	}
	if out.Page != 1 || out.Pages != 10 || out.NextCost != 1 {
		t.Errorf("page %d sur %d, suite a %d requete(s)", out.Page, out.Pages, out.NextCost)
	}
}

// Charger la suite fusionne les pages deja vues (depuis le cache) et la
// nouvelle, et classe le tout d'un seul tenant.
func TestChargerLaSuite(t *testing.T) {
	f := &pagedSearcher{total: 5000}
	h := newServer(f)
	search(t, h, quick("/api/search?q=yaml"))
	out := search(t, h, quick("/api/search?q=yaml&upto=2"))
	if len(out.Repos) != 2*pageSize {
		t.Errorf("%d depots apres la suite, attendu %d", len(out.Repos), 2*pageSize)
	}
	if f.calls != 2 {
		t.Errorf("%d appels, la premiere page devait revenir du cache", f.calls)
	}
	if out.Page != 2 {
		t.Errorf("page = %d", out.Page)
	}
}

// Une page incomplete est la derniere: aucune requete de plus.
func TestPasDePageAuDelaDuTotal(t *testing.T) {
	f := &pagedSearcher{total: 130}
	out := search(t, newServer(f), quick("/api/search?q=yaml&upto=5"))
	if f.calls != 2 || len(out.Repos) != 130 {
		t.Errorf("%d appels, %d depots, attendu 2 appels et 130 depots", f.calls, len(out.Repos))
	}
}

// GitHub s'arrete a mille resultats: dix pages de cent au plus.
func TestPagesBornees(t *testing.T) {
	f := &pagedSearcher{total: 50000}
	out := search(t, newServer(f), quick("/api/search?q=yaml&upto=40"))
	if f.lastPage != 10 || out.Page != 10 {
		t.Errorf("derniere page %d, page rendue %d, attendu 10", f.lastPage, out.Page)
	}
}
