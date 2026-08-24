// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func labels(sts []Strategy) []string {
	out := make([]string, len(sts))
	for i, s := range sts {
		out[i] = s.Label
	}
	return out
}

func TestQuickModeAsksOnce(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml", "parser"}, Language: "Go"}
	if got := Strategies(in, false); len(got) != 1 {
		t.Errorf("mode rapide = %d requetes, want 1: %v", len(got), labels(got))
	}
}

// Le coeur du mode approfondi: la meme question posee de plusieurs facons.
func TestDeepModeAsksSeveralWays(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml", "parser"}, Language: "Go"}
	got := Strategies(in, true)
	if len(got) < 4 {
		t.Fatalf("mode approfondi = %d requetes, want au moins 4: %v", len(got), labels(got))
	}

	var hasName, hasDesc, hasExact bool
	for _, s := range got {
		if strings.Contains(s.Query, "in:name") {
			hasName = true
		}
		if strings.Contains(s.Query, "in:description") {
			hasDesc = true
		}
		if strings.Contains(s.Query, `"yaml parser"`) {
			hasExact = true
		}
	}
	if !hasName || !hasDesc || !hasExact {
		t.Errorf("formulations manquantes: nom=%v description=%v exacte=%v", hasName, hasDesc, hasExact)
	}
}

// Nommer son projet d'apres un concept est un acte delibere; le mentionner
// dans un README peut etre une remarque en passant.
func TestNameStrategyOutweighsGeneralSearch(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml"}}
	var general, name float64
	for _, s := range Strategies(in, true) {
		if s.Label == "recherche generale" {
			general = s.Weight
		}
		if s.Label == "nom du depot" {
			name = s.Weight
		}
	}
	if name <= general {
		t.Errorf("poids nom=%v general=%v, le nom devait peser plus", name, general)
	}
}

// Combiner un filtre par sujet avec une restriction in:name exige les deux, ce
// qui est plus strict que chacun et ne trouve presque rien.
func TestQualifiedStrategiesDropTopics(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml"}, Topics: []string{"yaml-parser"}}
	for _, s := range Strategies(in, true) {
		if strings.Contains(s.Query, "in:") && strings.Contains(s.Query, "topic:") {
			t.Errorf("sujet et restriction combines: %q", s.Query)
		}
	}
}

func TestSingleTermHasNoExactPhrase(t *testing.T) {
	// Mettre un seul mot entre guillemets ne change rien et gaspille un appel.
	in := model.Intent{Terms: []string{"yaml"}}
	for _, s := range Strategies(in, true) {
		if s.Label == "expression exacte" {
			t.Error("un terme unique ne justifie pas une requete d'expression exacte")
		}
	}
}

func TestNoTermsNoStrategies(t *testing.T) {
	if got := Strategies(model.Intent{}, true); got != nil {
		t.Errorf("aucun terme: %v", labels(got))
	}
}
