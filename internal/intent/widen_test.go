// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func TestWidenProducesOneQueryPerVariant(t *testing.T) {
	in := model.Intent{Terms: []string{"parser", "yaml"}, Language: "Go", ExcludeForks: true}
	got := Widen(in, 5)
	if len(got) == 0 {
		t.Fatal("aucune variante produite pour un terme connu")
	}
	if len(got) > 5 {
		t.Errorf("%d requetes, la borne de 5 n'est pas respectee", len(got))
	}
	// Le langage reste: c'est une contrainte de l'utilisateur, pas une
	// consequence de la langue de description.
	for _, q := range got {
		if !strings.Contains(q, "language:Go") {
			t.Errorf("requete elargie sans le langage: %q", q)
		}
	}
}

// Mettre deux variantes dans la meme requete exigerait qu'un mot chinois et un
// mot russe apparaissent dans le meme depot, ce qui ne decrit rien.
func TestWidenSubstitutesOnlyTheHeadTerm(t *testing.T) {
	in := model.Intent{Terms: []string{"parser", "encryption"}}
	for _, q := range Widen(in, 3) {
		if strings.Contains(q, "parser") && !strings.Contains(q, "encryption") {
			t.Errorf("les deux termes devaient rester presents: %q", q)
		}
	}
}

// Une description ecrite dans une autre langue ne porte pas les sujets
// anglais: garder le filtre rendrait la requete elargie plus stricte que
// l'originale, ce qui va contre son but.
func TestWidenDropsTopicFacet(t *testing.T) {
	in := model.Intent{Terms: []string{"parser"}, Topics: []string{"yaml-parser"}}
	for _, q := range Widen(in, 3) {
		if strings.Contains(q, "topic:") {
			t.Errorf("le filtre par sujet devait tomber: %q", q)
		}
	}
}

func TestWidenIsEmptyForUnknownTerms(t *testing.T) {
	in := model.Intent{Terms: []string{"kubernetes", "grpc"}}
	if got := Widen(in, 5); len(got) != 0 {
		t.Errorf("des termes identiques partout n'ont pas de variante: %v", got)
	}
}

func TestWidenRespectsZeroBudget(t *testing.T) {
	in := model.Intent{Terms: []string{"parser"}}
	if got := Widen(in, 0); got != nil {
		t.Errorf("budget nul: %v", got)
	}
}

func TestHasVariants(t *testing.T) {
	if !HasVariants([]string{"grpc", "parser"}) {
		t.Error("un terme connu doit suffire")
	}
	if HasVariants([]string{"grpc", "kubernetes"}) {
		t.Error("aucun terme connu ne doit rien signaler")
	}
}
