// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"
)

func TestFrancaisGardeLesMotsTapes(t *testing.T) {
	in := French(Read("outil de chiffrement en ligne de commande, en go"))
	q := Query(in)
	for _, want := range []string{"chiffrement", `"ligne de commande"`, "language:Go"} {
		if !strings.Contains(q, want) {
			t.Errorf("requete %q sans %s", q, want)
		}
	}
	for _, bad := range []string{"encryption", "cli", "outil"} {
		if hasTerm(in.Terms, bad) {
			t.Errorf("%q ne doit pas etre cherche en francais: %v", bad, in.Terms)
		}
	}
}

// La lecture suit: ce que l'interface affiche est ce qui part dans la requete.
func TestFrancaisLectureCoherente(t *testing.T) {
	in := French(Read("détection d'intrusion réseau"))
	for _, s := range in.Reading {
		if s.Role == "terme" && !hasTerm(in.Terms, s.Value) {
			t.Errorf("segment %q annonce %q, absent des termes %v", s.Text, s.Value, in.Terms)
		}
	}
	if !hasTerm(in.Terms, `"détection d'intrusion"`) || !hasTerm(in.Terms, "réseau") {
		t.Errorf("termes = %v", in.Terms)
	}
}

func TestFrancaisSansTermeRendLIntention(t *testing.T) {
	in := Read("du rust")
	if got := French(in); Query(got) != Query(in) {
		t.Errorf("requete changee: %q, attendu %q", Query(got), Query(in))
	}
}

// Une expression deja entre guillemets ne donne ni sujet ni expression exacte
// imbriquee: la requete resterait invalide.
func TestStrategiesAvecExpressionCitee(t *testing.T) {
	in := French(Read("scanner de ports en ligne de commande"))
	for _, st := range Strategies(in, true) {
		if strings.Contains(st.Query, `""`) || strings.Contains(st.Query, `topic:"`) {
			t.Errorf("%s: requete cassee %q", st.Label, st.Query)
		}
	}
}

func TestPlurielsGeneriquesEcartes(t *testing.T) {
	in := Read("bibliothèques go maintenues")
	if hasTerm(in.Terms, "bibliotheques") {
		t.Errorf("pluriel generique cherche: %v", in.Terms)
	}
}
