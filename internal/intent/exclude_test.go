// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

// Ce que la phrase demande d'ecarter devient un NOT, et n'est jamais cherche.
func TestExclusions(t *testing.T) {
	cases := map[string]struct {
		excluded string
		term     string
	}{
		"scanner de ports en go, pas de nmap":   {"nmap", "port-scanner"},
		"pot de miel sauf cowrie":               {"cowrie", "honeypot"},
		"honeypot -cowrie":                      {"cowrie", "honeypot"},
		"énumération hors active directory":     {"active-directory", "enumeration"},
		"sauvegarde, pas d'interface graphique": {"gui", "backup"},
		"fuzzer except afl":                     {"afl", "fuzzer"},
	}
	for phrase, want := range cases {
		t.Run(phrase, func(t *testing.T) {
			in := Read(phrase)
			if !hasTerm(in.Exclude, want.excluded) {
				t.Errorf("exclusions = %v, attendu %s", in.Exclude, want.excluded)
			}
			if hasTerm(in.Terms, want.excluded) || !hasTerm(in.Terms, want.term) {
				t.Errorf("termes = %v", in.Terms)
			}
			if q := Query(in); !strings.Contains(q, "NOT "+want.excluded) {
				t.Errorf("requete = %q", q)
			}
		})
	}
}

// "sans" decrit une caracteristique: un outil sans agent est agentless, pas
// un outil dont on ecarte le mot agent.
func TestSansNEstPasUneExclusion(t *testing.T) {
	cases := map[string]string{
		"supervision sans agent":       "agentless",
		"maliciel sans fichier":        "fileless",
		"parseur yaml sans dependance": "zero-dependency",
		"conteneurs sans root":         "rootless",
	}
	for phrase, want := range cases {
		in := Read(phrase)
		if len(in.Exclude) != 0 || !hasTerm(in.Terms, want) {
			t.Errorf("%s: termes = %v, exclusions = %v", phrase, in.Terms, in.Exclude)
		}
	}
}

// Un marqueur doit etre un mot entier: "horsepower" n'ecarte rien.
func TestMarqueurMotEntier(t *testing.T) {
	in := Read("horsepower")
	if len(in.Exclude) != 0 || !hasTerm(in.Terms, "horsepower") {
		t.Errorf("termes = %v, exclusions = %v", in.Terms, in.Exclude)
	}
	if in := Read("scanner pas de"); len(in.Exclude) != 0 {
		t.Errorf("marqueur sans mot: exclusions = %v", in.Exclude)
	}
}

// GitHub refuse plus de cinq NOT: les exclusions au-dela sont dites, pas
// envoyees.
func TestExclusionsBornees(t *testing.T) {
	in := Read("scanner, pas de nmap, pas de masscan, sauf zmap, -rustscan, -naabu")
	if len(in.Exclude) != maxExclusions {
		t.Errorf("%d exclusions, attendu %d: %v", len(in.Exclude), maxExclusions, in.Exclude)
	}
	cut := false
	for _, s := range in.Reading {
		if s.Role == model.RoleOverLimits && s.Value == "naabu" {
			cut = true
		}
	}
	if !cut {
		t.Error("l'exclusion en trop doit etre signalee")
	}
}

// Une requete faite de qualificatifs seuls (strategie par sujet) ne porte pas
// de NOT, qui n'aurait rien a quoi s'appliquer.
func TestPasDeNotSansTerme(t *testing.T) {
	in := Read("pot de miel sauf cowrie")
	for _, st := range Strategies(in, true) {
		if strings.HasPrefix(st.Label, "sujet") && strings.Contains(st.Query, "NOT") {
			t.Errorf("strategie par sujet avec NOT: %q", st.Query)
		}
		if !strings.HasPrefix(st.Label, "sujet") && !strings.Contains(st.Query, "NOT cowrie") {
			t.Errorf("%s sans l'exclusion: %q", st.Label, st.Query)
		}
	}
}

func TestLicenceLue(t *testing.T) {
	cases := map[string]string{
		"scanner de vulnérabilités sous licence mit": "mit",
		"fuzzer licence apache":                      "apache-2.0",
		"honeypot license gplv3":                     "gpl-3.0",
	}
	for phrase, want := range cases {
		in := Read(phrase)
		if in.License != want || !strings.Contains(Query(in), "license:"+want) {
			t.Errorf("%s: licence = %q, requete = %q", phrase, in.License, Query(in))
		}
		if hasTerm(in.Terms, "licence") || hasTerm(in.Terms, "license") {
			t.Errorf("%s: le mot licence ne doit pas etre cherche: %v", phrase, in.Terms)
		}
	}
	// Une licence inconnue laisse les mots a la lecture ordinaire.
	if in := Read("gestion de licence logicielle"); in.License != "" {
		t.Errorf("licence inventee: %q", in.License)
	}
}

// Les filtres de la page s'ajoutent a la requete: licence, auteur, listes.
func TestFiltresLicenceAuteurListes(t *testing.T) {
	in := Read("pot de miel ssh licence mit")
	in.Filters = model.Filters{License: "apache-2.0", Owner: "mushorg", NoLists: true}
	q := Query(in)
	for _, want := range []string{"license:apache-2.0", "user:mushorg", "NOT awesome", "-topic:awesome-list"} {
		if !strings.Contains(q, want) {
			t.Errorf("requete %q sans %s", q, want)
		}
	}
	if strings.Contains(q, "license:mit") {
		t.Errorf("la licence choisie doit remplacer celle de la phrase: %q", q)
	}
	// Une question sur les listes awesome garde le mot.
	in = Read("awesome honeypot")
	in.Filters.NoLists = true
	if strings.Contains(Query(in), "NOT awesome") {
		t.Errorf("la question contient awesome: %q", Query(in))
	}
}

// En francais, le mot ecarte l'est tel qu'il a ete tape.
func TestFrancaisGardeLExclusionTapee(t *testing.T) {
	in := French(Read("chiffrement en ligne de commande, pas de interface graphique"))
	if !hasTerm(in.Exclude, "interface graphique") {
		t.Errorf("exclusions = %v", in.Exclude)
	}
	if q := Query(in); !strings.Contains(q, `NOT "interface graphique"`) {
		t.Errorf("requete = %q", q)
	}
}
