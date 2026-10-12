// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"regexp"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/intent"
	"github.com/terrypsv/Quaero/internal/model"
)

// Un exemple propose sur la page doit montrer l'outil sous son meilleur jour:
// au moins un mot-cle, aucun mot generique ni coupe. Un exemple qui laisse un
// mot de cote apprend a l'utilisateur a mal ecrire sa phrase.
func TestExemplesLisibles(t *testing.T) {
	page := string(indexHTML)
	start := strings.Index(page, "var ALL_EXAMPLES = [")
	end := strings.Index(page[start:], "];")
	if start < 0 || end < 0 {
		t.Fatal("liste ALL_EXAMPLES introuvable dans la page")
	}
	examples := regexp.MustCompile(`(?m)^\s*"([^"]+)",?\s*$`).FindAllStringSubmatch(page[start:start+end], -1)
	if len(examples) < 10 {
		t.Fatalf("%d exemples seulement", len(examples))
	}
	for _, m := range examples {
		in := intent.Read(m[1])
		if len(in.Terms) == 0 {
			t.Errorf("%q ne donne aucun mot-cle", m[1])
		}
		for _, s := range in.Reading {
			if s.Role == model.RoleGeneric || s.Role == model.RoleOverLimits {
				t.Errorf("%q laisse %q de cote (%s)", m[1], s.Text, s.Role)
			}
		}
	}
}
