// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

// La lecture rend la phrase telle qu'elle a ete tapee: casse, accents et
// ponctuation compris. Sinon l'interface montrerait des mots que personne n'a
// ecrits.
func TestLectureRendLaPhraseExacte(t *testing.T) {
	for _, phrase := range []string{
		"bibliothèque yaml en go maintenue et populaire",
		"Parseur de JOURNAUX en Rust, au moins 500 étoiles !",
		"client en ligne de commande pour base de données, y compris les forks",
		"解析 yaml en go",
		"  espaces   multiples  ",
		"",
	} {
		var b strings.Builder
		for _, s := range Read(phrase).Reading {
			b.WriteString(s.Text)
		}
		if b.String() != phrase {
			t.Errorf("lecture de %q recompose %q", phrase, b.String())
		}
	}
}

func roles(in model.Intent) map[string]model.Segment {
	got := map[string]model.Segment{}
	for _, s := range in.Reading {
		if s.Role != "" {
			got[s.Text] = s
		}
	}
	return got
}

func TestLectureDitCeQueChaqueMotADonne(t *testing.T) {
	got := roles(Read("bibliothèque yaml en go maintenue et populaire"))
	want := map[string][2]string{
		"bibliothèque": {model.RoleGeneric, ""},
		"yaml":         {model.RoleTerm, "yaml"},
		"en":           {model.RoleEmpty, ""},
		"go":           {model.RoleLanguage, "Go"},
		"maintenue":    {model.RoleRecency, "180"},
		"et":           {model.RoleEmpty, ""},
		"populaire":    {model.RoleStars, "500"},
	}
	for text, w := range want {
		s, ok := got[text]
		if !ok {
			t.Errorf("%q absent de la lecture: %v", text, got)
			continue
		}
		if s.Role != w[0] || s.Value != w[1] {
			t.Errorf("%q lu %s/%s, attendu %s/%s", text, s.Role, s.Value, w[0], w[1])
		}
	}
}

func TestLectureGardeLesExpressionsEntieres(t *testing.T) {
	got := roles(Read("Parseur de journaux en Rust, au moins 500 étoiles"))
	if s := got["au moins 500 étoiles"]; s.Role != model.RoleStars || s.Value != "500" {
		t.Errorf("plancher d'etoiles mal lu: %v", got)
	}
	if s := got["journaux"]; s.Role != model.RoleTerm || s.Value != "logs" {
		t.Errorf("le terme traduit doit donner sa traduction: %v", got)
	}
	got = roles(Read("outil en ligne de commande, y compris les forks"))
	if s := got["ligne de commande"]; s.Role != model.RoleTerm || s.Value != "cli" {
		t.Errorf("expression multi-mots mal lue: %v", got)
	}
	if s := got["y compris les forks"]; s.Role != model.RoleForks {
		t.Errorf("inclusion des forks mal lue: %v", got)
	}
}

// Une forme flechie ne laisse plus de reste: "maintenues" donnait le terme
// "es", qui suffisait a vider les resultats puisque GitHub combine les termes.
func TestFlexionSansReste(t *testing.T) {
	in := Read("bibliotheques go maintenues")
	if in.PushedWithinDays != 180 {
		t.Errorf("recence non lue: %d jours", in.PushedWithinDays)
	}
	for _, bad := range []string{"es", "s"} {
		if hasTerm(in.Terms, bad) {
			t.Errorf("reste de flexion cherche comme terme: %v", in.Terms)
		}
	}
}

// Un mot n'est reconnu qu'a partir de son debut: "inactif" contient "actif",
// mais demande exactement l'inverse.
func TestMotReconnuDepuisSonDebut(t *testing.T) {
	in := Read("un outil inactif")
	if in.PushedWithinDays != 0 {
		t.Errorf("inactif lu comme une demande de recence: %d jours", in.PushedWithinDays)
	}
	if !hasTerm(in.Terms, "inactif") {
		t.Errorf("inactif doit rester un terme: %v", in.Terms)
	}
}

func TestTermesAuDelaDeQuatreSignales(t *testing.T) {
	got := roles(Read("alpha beta gamma delta epsilon"))
	if got["epsilon"].Role != model.RoleOverLimits {
		t.Errorf("le cinquieme terme doit etre signale comme coupe: %v", got)
	}
	if got["alpha"].Role != model.RoleTerm {
		t.Errorf("les quatre premiers restent des termes: %v", got)
	}
}
