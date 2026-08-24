// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package rank

import (
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/model"
)

var fixedNow = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func init() {
	now = func() time.Time { return fixedNow }
}

func repo(name string, stars int, daysSincePush int) model.Repo {
	return model.Repo{
		FullName: "owner/" + name,
		Owner:    "owner",
		Name:     name,
		Stars:    stars,
		License:  "MIT",
		PushedAt: fixedNow.AddDate(0, 0, -daysSincePush),
	}
}

func TestHealthLevels(t *testing.T) {
	cases := map[int]string{
		1:    LevelHealthy,
		89:   LevelHealthy,
		200:  LevelCalm,
		400:  LevelDormant,
		1000: LevelAbandoned,
	}
	for days, want := range cases {
		if got := Rate(repo("x", 10, days)).Level; got != want {
			t.Errorf("%d jours: niveau = %q, want %q", days, got, want)
		}
	}
}

func TestArchivedBeatsEverything(t *testing.T) {
	r := repo("x", 50000, 1)
	r.Archived = true
	h := Rate(r)
	if h.Level != LevelArchived {
		t.Errorf("niveau = %q, want %q", h.Level, LevelArchived)
	}
}

// Un depot sans date d'envoi est inconnu, pas sain. Affirmer la sante a partir
// d'une donnee absente est le defaut que toute la suite cherche a eviter.
func TestMissingPushDateIsNotHealthy(t *testing.T) {
	r := model.Repo{FullName: "owner/x", Name: "x", Stars: 100}
	h := Rate(r)
	if h.Level == LevelHealthy {
		t.Error("une date absente ne doit jamais produire un verdict sain")
	}
	if h.DaysSincePush != -1 {
		t.Errorf("anciennete = %d, want -1 pour inconnu", h.DaysSincePush)
	}
}

func TestIssueRatioDowngradesHealthy(t *testing.T) {
	r := repo("x", 1000, 10)
	r.OpenIssues = 400 // 40 pour cent
	h := Rate(r)
	if h.Level != LevelCalm {
		t.Errorf("niveau = %q, un ratio d'issues eleve doit degrader", h.Level)
	}
}

func TestMissingLicenseIsNoted(t *testing.T) {
	r := repo("x", 10, 10)
	r.License = ""
	found := false
	for _, n := range Rate(r).Notes {
		if contains(n, "licence") {
			found = true
		}
	}
	if !found {
		t.Error("une licence absente doit etre signalee")
	}
}

// Le coeur du classement: un nom exact bat la popularite brute.
func TestExactNameBeatsPopularity(t *testing.T) {
	exact := repo("yaml", 200, 20)
	famous := repo("kubernetes", 90000, 5)
	famous.Description = "container orchestration, uses yaml everywhere"

	in := model.Intent{Terms: []string{"yaml"}}
	out := Score([]model.Repo{famous, exact}, in, SortRelevance)

	if out[0].Name != "yaml" {
		t.Errorf("premier = %q, le nom exact devait primer sur %d etoiles", out[0].Name, famous.Stars)
	}
}

// Un projet arrete doit passer derriere une alternative vivante comparable.
func TestAbandonedFallsBehind(t *testing.T) {
	alive := repo("parser", 300, 15)
	dead := repo("parser-old", 3000, 1200)

	in := model.Intent{Terms: []string{"parser"}}
	out := Score([]model.Repo{dead, alive}, in, SortRelevance)

	if out[0].Name != "parser" {
		t.Errorf("premier = %q, le projet vivant devait primer", out[0].Name)
	}
}

func TestCoveringAllTermsIsRewarded(t *testing.T) {
	both := repo("yaml-parser", 100, 10)
	one := repo("yaml", 100, 10)

	in := model.Intent{Terms: []string{"yaml", "parser"}}
	out := Score([]model.Repo{one, both}, in, SortRelevance)

	if out[0].Name != "yaml-parser" {
		t.Errorf("premier = %q, couvrir tous les termes devait primer", out[0].Name)
	}
}

func TestLanguageMatchIsRewarded(t *testing.T) {
	goRepo := repo("thing", 100, 10)
	goRepo.Language = "Go"
	pyRepo := repo("thing", 100, 10)
	pyRepo.Language = "Python"

	in := model.Intent{Terms: []string{"thing"}, Language: "Go"}
	out := Score([]model.Repo{pyRepo, goRepo}, in, SortRelevance)

	if out[0].Language != "Go" {
		t.Errorf("premier langage = %q, want Go", out[0].Language)
	}
}

func TestTopicMatchCounts(t *testing.T) {
	withTopic := repo("alpha", 100, 10)
	withTopic.Topics = []string{"yaml"}
	without := repo("beta", 100, 10)

	in := model.Intent{Terms: []string{"yaml"}}
	out := Score([]model.Repo{without, withTopic}, in, SortRelevance)

	if out[0].Name != "alpha" {
		t.Errorf("premier = %q, le sujet correspondant devait primer", out[0].Name)
	}
}

// Chaque point doit etre justifiable: un classement inexplicable est un
// classement auquel personne ne peut se fier.
func TestEveryRankedRepoExplainsItself(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml"}, Language: "Go"}
	r := repo("yaml", 100, 10)
	r.Language = "Go"
	out := Score([]model.Repo{r}, in, SortRelevance)

	if len(out[0].Why) == 0 {
		t.Error("un resultat classe doit dire pourquoi")
	}
}

func TestScoreDoesNotMutateInput(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml"}}
	original := repo("yaml", 100, 10)
	input := []model.Repo{original}
	_ = Score(input, in, SortRelevance)

	if input[0].Score != 0 || len(input[0].Why) != 0 {
		t.Error("Score ne doit pas modifier la tranche recue")
	}
}

func TestStarsAreOnlyATiebreaker(t *testing.T) {
	// Deux depots identiques sauf les etoiles: le plus populaire passe devant,
	// mais l'ecart de score doit rester modeste.
	small := repo("yaml", 10, 10)
	big := repo("yaml", 100000, 10)

	in := model.Intent{Terms: []string{"yaml"}}
	out := Score([]model.Repo{small, big}, in, SortRelevance)

	if out[0].Stars != 100000 {
		t.Error("a pertinence egale, la popularite departage")
	}
	if out[0].Score-out[1].Score > 10 {
		t.Errorf("ecart de score %.1f trop grand, la popularite ne doit pas ecraser", out[0].Score-out[1].Score)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
