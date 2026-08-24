// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"
)

// Le defaut qui rendait l'outil inutilisable: "bibliotheque" partait tel quel
// vers GitHub, dont les depots sont decrits en anglais. Les termes etant
// combines en ET, ce seul mot vidait tout le resultat.
func TestGenericNounsAreDropped(t *testing.T) {
	in := Read("une bibliotheque go pour parser du yaml")
	for _, bad := range []string{"bibliotheque", "librairie", "outil", "module"} {
		if hasTerm(in.Terms, bad) {
			t.Errorf("mot generique conserve: %q dans %v", bad, in.Terms)
		}
	}
	if !hasTerm(in.Terms, "yaml") {
		t.Errorf("le terme utile a disparu: %v", in.Terms)
	}
}

func TestGenericRemovalIsReported(t *testing.T) {
	in := Read("un outil go de scan")
	found := false
	for _, e := range in.Explain {
		if strings.Contains(e, "generique") {
			found = true
		}
	}
	if !found {
		t.Errorf("le retrait doit etre explique: %v", in.Explain)
	}
}

func TestTechnicalTermsAreTranslated(t *testing.T) {
	cases := map[string]string{
		"un outil de chiffrement":      "encryption",
		"une lib de compression":       "compression",
		"un scanner de vulnerabilites": "vulnerability",
		"outil de sauvegarde":          "backup",
		"gestion de secrets":           "secrets",
		"analyse de journaux":          "logs",
	}
	for phrase, want := range cases {
		t.Run(phrase, func(t *testing.T) {
			if !hasTerm(Read(phrase).Terms, want) {
				t.Errorf("terme %q absent de %v", want, Read(phrase).Terms)
			}
		})
	}
}

// Un mot rare non traduit est souvent le plus precis de la phrase: il doit
// passer intact.
func TestUnknownWordsPassThrough(t *testing.T) {
	if !hasTerm(Read("un client kubernetes").Terms, "kubernetes") {
		t.Error("un terme technique inconnu du glossaire doit etre conserve")
	}
}

func TestDuplicateTermsAreCollapsed(t *testing.T) {
	// "tests" et "test" se traduisent tous deux en "testing".
	in := Read("un framework de test et de tests")
	count := 0
	for _, term := range in.Terms {
		if term == "testing" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("terme duplique apres traduction: %v", in.Terms)
	}
}

// "ligne de commande" traduit mot a mot ne veut rien dire; il faut le
// reconnaitre comme un tout.
func TestMultiWordExpressions(t *testing.T) {
	cases := map[string]string{
		"un outil en ligne de commande":       "cli",
		"un client de base de donnees":        "database",
		"une lib d apprentissage automatique": "machine-learning",
		"des tests bout en bout":              "end-to-end",
		"un gestionnaire de mot de passe":     "password",
		"traitement en temps reel":            "realtime",
	}
	for phrase, want := range cases {
		t.Run(phrase, func(t *testing.T) {
			if !hasTerm(Read(phrase).Terms, want) {
				t.Errorf("terme %q absent de %v", want, Read(phrase).Terms)
			}
		})
	}
}

// Le piege que la reconnaissance de groupe evite: traduire mot a mot
// donnerait "database data", et "data" seul ramene la moitie de GitHub.
func TestMultiWordAvoidsNoiseTerms(t *testing.T) {
	in := Read("un client de base de donnees en go")
	if hasTerm(in.Terms, "data") {
		t.Errorf("terme parasite issu d'une traduction mot a mot: %v", in.Terms)
	}
}

// Au-dela de quatre termes en ET, la probabilite qu'un meme depot les porte
// tous s'effondre.
func TestTermsAreCappedAtFour(t *testing.T) {
	in := Read("parser yaml json toml xml ini csv")
	if len(in.Terms) > 4 {
		t.Errorf("termes = %d, want au plus 4: %v", len(in.Terms), in.Terms)
	}
}
