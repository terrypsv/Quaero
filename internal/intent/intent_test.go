// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"
	"time"
)

func init() {
	// Fixed clock: a query built today and the same query built in six months
	// must produce the same string, otherwise the tests rot.
	now = func() time.Time { return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC) }
}

func hasTerm(terms []string, want string) bool {
	for _, t := range terms {
		if t == want {
			return true
		}
	}
	return false
}

func TestReadsLanguage(t *testing.T) {
	for phrase, want := range map[string]string{
		"une bibliotheque go pour du yaml": "Go",
		"un outil rust de scan":            "Rust",
		"client python pour elasticsearch": "Python",
		"framework typescript de tests":    "TypeScript",
		"quelque chose en golang":          "Go",
	} {
		t.Run(phrase, func(t *testing.T) {
			if got := Read(phrase).Language; got != want {
				t.Errorf("langage = %q, want %q", got, want)
			}
		})
	}
}

func TestLanguageIsRemovedFromTerms(t *testing.T) {
	// Laisser "go" dans les termes ferait remonter tous les depots dont le nom
	// contient go, ce qui noie la vraie demande.
	in := Read("une bibliotheque go pour parser du yaml")
	if hasTerm(in.Terms, "go") {
		t.Errorf("le langage ne doit pas rester dans les termes: %v", in.Terms)
	}
	if !hasTerm(in.Terms, "yaml") {
		t.Errorf("le terme utile manque: %v", in.Terms)
	}
}

func TestStopWordsAreDropped(t *testing.T) {
	in := Read("je cherche une bibliotheque pour parser du yaml")
	for _, bad := range []string{"je", "cherche", "une", "pour", "du"} {
		if hasTerm(in.Terms, bad) {
			t.Errorf("mot vide conserve: %q dans %v", bad, in.Terms)
		}
	}
}

func TestRecencyPhrases(t *testing.T) {
	cases := map[string]int{
		"un outil go encore maintenu":       180,
		"une lib rust activement maintenue": 90,
		"un projet python recent":           90,
		"a go tool still maintained":        180,
	}
	for phrase, want := range cases {
		t.Run(phrase, func(t *testing.T) {
			if got := Read(phrase).PushedWithinDays; got != want {
				t.Errorf("fenetre = %d, want %d", got, want)
			}
		})
	}
}

func TestPopularityPhrases(t *testing.T) {
	if got := Read("une lib go tres populaire").MinStars; got != 5000 {
		t.Errorf("etoiles = %d, want 5000", got)
	}
	if got := Read("un outil rust populaire").MinStars; got != 500 {
		t.Errorf("etoiles = %d, want 500", got)
	}
}

func TestExplicitStarFloorWins(t *testing.T) {
	// Un chiffre explicite est plus precis qu'un adjectif: il doit primer.
	in := Read("une lib go populaire avec au moins 2000 etoiles")
	if in.MinStars != 2000 {
		t.Errorf("etoiles = %d, want 2000", in.MinStars)
	}
}

func TestForksAndArchivedExcludedByDefault(t *testing.T) {
	in := Read("un outil go")
	if !in.ExcludeForks || !in.ExcludeArchived {
		t.Error("forks et archives doivent etre ecartes par defaut")
	}
}

func TestDefaultsCanBeReversed(t *testing.T) {
	if Read("un outil go y compris les forks").ExcludeForks {
		t.Error("la phrase demandait les forks")
	}
	if Read("un outil go y compris archives").ExcludeArchived {
		t.Error("la phrase demandait les archives")
	}
}

func TestAccentsAreNormalised(t *testing.T) {
	// La meme demande tapee avec ou sans accents doit produire le meme resultat.
	withAccents := Read("une bibliothèque go récente")
	without := Read("une bibliotheque go recente")
	if withAccents.PushedWithinDays != without.PushedWithinDays {
		t.Errorf("accents: %d != %d", withAccents.PushedWithinDays, without.PushedWithinDays)
	}
}

func TestExplainReportsEveryFacet(t *testing.T) {
	// L'utilisateur doit pouvoir voir comment sa phrase a ete lue, sinon il ne
	// peut pas distinguer un mauvais resultat d'une question mal comprise.
	in := Read("une lib go populaire et maintenue")
	if len(in.Explain) < 3 {
		t.Errorf("facettes expliquees insuffisantes: %v", in.Explain)
	}
}

func TestQueryRendersQualifiers(t *testing.T) {
	q := Query(Read("une bibliotheque go pour yaml, maintenue, populaire"))
	for _, want := range []string{"yaml", "language:Go", "stars:>=500", "pushed:>=", "fork:false", "archived:false"} {
		if !strings.Contains(q, want) {
			t.Errorf("requete %q ne contient pas %q", q, want)
		}
	}
}

func TestQueryUsesFixedClock(t *testing.T) {
	// 90 jours avant le 24 aout 2026 = 26 mai 2026.
	q := Query(Read("un outil go recent"))
	if !strings.Contains(q, "pushed:>=2026-05-26") {
		t.Errorf("date attendue absente de %q", q)
	}
}

func TestLanguageOnlyStillSearches(t *testing.T) {
	// "du rust" est une demande legitime: ne pas produire une requete vide.
	in := Read("du rust")
	if len(in.Terms) == 0 {
		t.Error("une demande de langage seul doit garder un terme")
	}
}

func TestHyphenatedWordsBecomeTopics(t *testing.T) {
	in := Read("un outil pour machine-learning")
	found := false
	for _, topic := range in.Topics {
		if topic == "machine-learning" {
			found = true
		}
	}
	if !found {
		t.Errorf("sujet attendu absent: %v", in.Topics)
	}
}
