// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func TestLadderRelaxesFromLeastToMostMeaningful(t *testing.T) {
	in := model.Intent{
		Terms:            []string{"yaml", "parser", "streaming"},
		Language:         "Go",
		MinStars:         500,
		PushedWithinDays: 90,
		Topics:           []string{"yaml-parser"},
		ExcludeForks:     true,
		ExcludeArchived:  true,
	}
	steps := Ladder(in)
	if len(steps) < 4 {
		t.Fatalf("echelle trop courte: %d etapes", len(steps))
	}

	// La fraicheur est une preference, pas la question: elle part en premier.
	if !strings.Contains(steps[0].Reason, "fraicheur") {
		t.Errorf("premiere etape = %q, la fraicheur devait ceder en premier", steps[0].Reason)
	}
	// Les termes sont la question elle-meme: ils partent en dernier.
	last := steps[len(steps)-1].Reason
	if !strings.Contains(last, "terme") && !strings.Contains(last, "forks") {
		t.Errorf("derniere etape = %q, les termes devaient ceder en dernier", last)
	}
}

func TestLadderNeverEmptiesTheQuestion(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml", "parser"}, Language: "Go"}
	for _, step := range Ladder(in) {
		if len(step.Intent.Terms) == 0 {
			t.Error("une etape ne doit jamais supprimer tous les termes")
		}
		if step.Query == "" {
			t.Error("une etape ne doit jamais produire une requete vide")
		}
	}
}

func TestLadderIsEmptyWhenNothingToRelax(t *testing.T) {
	in := model.Intent{Terms: []string{"yaml"}}
	if steps := Ladder(in); len(steps) != 0 {
		t.Errorf("rien a desserrer, mais %d etape(s): %v", len(steps), steps)
	}
}

// Un resultat obtenu apres desserrage reste un resultat; obtenu en silence, ce
// serait un mensonge.
func TestDescribeNamesWhatWasGivenUp(t *testing.T) {
	got := Describe([]string{"sans la contrainte de fraicheur", "sans le plancher d'etoiles"})
	if !strings.Contains(got, "fraicheur") || !strings.Contains(got, "plancher") {
		t.Errorf("description incomplete: %q", got)
	}
	if Describe(nil) != "" {
		t.Error("aucun desserrage ne doit produire aucun message")
	}
}
