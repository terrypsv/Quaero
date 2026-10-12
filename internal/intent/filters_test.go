// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func filtered() model.Intent {
	in := Read("pot de miel ssh")
	in.Filters = model.Filters{
		Language:         "Python",
		Topics:           []string{"threat-intelligence"},
		MinStars:         100,
		PushedWithinDays: 90,
	}
	return in
}

// Un critere choisi parmi les resultats est une exigence: chaque formulation
// de la question le porte, sinon les depots trouves par le nom ou la
// description passeraient a travers.
func TestFiltresDansChaqueStrategie(t *testing.T) {
	in := filtered()
	strategies := Strategies(in, true)
	if len(strategies) < 3 {
		t.Fatalf("seulement %d strategies", len(strategies))
	}
	for _, st := range strategies {
		for _, want := range []string{"language:Python", "topic:threat-intelligence", "stars:>=100", "pushed:>="} {
			if !strings.Contains(st.Query, want) {
				t.Errorf("%s: %q ne contient pas %s", st.Label, st.Query, want)
			}
		}
	}
}

func TestFiltresDansLesVariantesDeLangue(t *testing.T) {
	in := filtered()
	in.Terms = []string{"honeypot"}
	alts := Widen(in, 6)
	if len(alts) == 0 {
		t.Fatal("aucune variante pour honeypot")
	}
	for _, q := range alts {
		if !strings.Contains(q, "topic:threat-intelligence") || !strings.Contains(q, "language:Python") {
			t.Errorf("variante sans les filtres: %q", q)
		}
	}
}

// Le langage choisi remplace celui de la phrase: deux qualificatifs language:
// se combinent en OU chez GitHub et elargiraient la recherche.
func TestLangageChoisiRemplaceLaPhrase(t *testing.T) {
	in := Read("scanner de ports en go")
	in.Filters.Language = "Rust"
	q := Query(in)
	if strings.Contains(q, "language:Go") || !strings.Contains(q, "language:Rust") {
		t.Errorf("requete = %q, attendu language:Rust seul", q)
	}
}

// Le plus exigeant des deux l'emporte: plus d'etoiles, fenetre plus courte.
func TestCriteresLesPlusStricts(t *testing.T) {
	in := Read("fuzzer populaire, maintenu")
	in.Filters.MinStars = 100
	in.Filters.PushedWithinDays = 90
	q := Query(in)
	if !strings.Contains(q, "stars:>=500") {
		t.Errorf("requete = %q, la phrase demandait deja 500 etoiles", q)
	}
	if !strings.Contains(q, "pushed:>="+daysAgo(90)) {
		t.Errorf("requete = %q, la fenetre de 90 jours doit l'emporter", q)
	}
}

// Le desserrage ne touche jamais aux filtres, et ne propose pas une etape qui
// renverrait la meme requete.
func TestDesserrageGardeLesFiltres(t *testing.T) {
	in := filtered()
	in.PushedWithinDays = 180
	seen := map[string]bool{Query(in): true}
	for _, step := range Ladder(in) {
		if seen[step.Query] {
			t.Errorf("etape %q renvoie une requete deja essayee: %q", step.Reason, step.Query)
		}
		seen[step.Query] = true
		if !strings.Contains(step.Query, "topic:threat-intelligence") || !strings.Contains(step.Query, "language:Python") {
			t.Errorf("etape %q a perdu un filtre: %q", step.Reason, step.Query)
		}
	}
}
