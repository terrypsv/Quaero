// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"fmt"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// EvidenceEngine est le type de preuve qui nomme le moteur ayant produit un
// constat. Un constat fusionne en porte un par moteur d'accord.
const EvidenceEngine = "engine"

// enginePriority departage deux constats de meme gravite sur la meme
// vulnerabilite. govulncheck passe devant: lui seul sait si le code fautif est
// reellement appele, ce qu'osv-scanner ne mesure pas.
var enginePriority = map[string]int{
	"govulncheck": 3,
	"gosec":       2,
	"semgrep":     2,
	"osv-scanner": 1,
}

// uniqueIDs rend chaque identifiant unique dans le rapport. Deux constats de la
// meme regle sur la meme ligne, ou deux chemins que l'assainissement ramene a la
// meme forme (a/js:3 et a.js:3), porteraient sinon le meme identifiant, et le
// brouillon de l'un s'ouvrirait pour l'autre. Le premier garde l'identifiant,
// les suivants prennent -2, -3, dans l'ordre des moteurs.
func uniqueIDs(fs []finding.Finding) []finding.Finding {
	seen := make(map[string]bool, len(fs))
	for _, f := range fs {
		seen[f.ID] = true
	}
	count := map[string]int{}
	for i := range fs {
		id := fs[i].ID
		count[id]++
		if count[id] == 1 {
			continue
		}
		n := count[id]
		next := fmt.Sprintf("%s-%d", id, n)
		for seen[next] {
			n++
			next = fmt.Sprintf("%s-%d", id, n)
		}
		count[id] = n
		seen[next] = true
		fs[i].ID = next
	}
	return fs
}

// EvidenceMerged porte le titre d'un constat fusionne dans un autre, avec son
// moteur: rien de ce qu'un moteur a dit ne disparait du rapport.
const EvidenceMerged = "fusionne"

// mergeSameLine regroupe les constats de code que deux moteurs differents
// posent sur la meme ligne du meme fichier. semgrep et gosec relevent souvent
// le meme appel (dangerous-exec-command et G204 sur un exec.Command), sous
// deux CWE voisines qui ne se recoupent pas: c'est un seul endroit a revoir,
// donc un seul constat. Le plus grave reste, l'autre s'ajoute a sa provenance
// et a ses references.
//
// Deux regles du meme moteur sur la meme ligne restent deux constats: le
// moteur les a voulues distinctes. Les constats de dependances et ceux sur le
// scan lui-meme ne sont pas concernes.
func mergeSameLine(fs []finding.Finding) []finding.Finding {
	var kept []finding.Finding
	index := map[string][]int{} // fichier:ligne -> positions dans kept
	for _, f := range fs {
		key := lineKey(f)
		if key == "" {
			kept = append(kept, f)
			continue
		}
		// Le premier constat de la ligne qui ne partage aucun moteur avec f
		// l'accueille: semgrep A, gosec B, semgrep C, gosec D donnent A+B et
		// C+D, quel que soit l'ordre.
		pos := -1
		for _, p := range index[key] {
			if !sharesEngine(f, kept[p]) {
				pos = p
				break
			}
		}
		if pos < 0 {
			kept = append(kept, f)
			index[key] = append(index[key], len(kept)-1)
			continue
		}
		a, b := kept[pos], f
		if better(f, kept[pos]) {
			a, b = f, kept[pos]
		}
		kept[pos] = absorb(a, b)
	}
	return kept
}

// lineKey rend fichier:ligne pour un constat de code sans identifiant public,
// ou "" s'il ne s'y prete pas.
func lineKey(f finding.Finding) string {
	if f.Target == nil || f.Target.Type != "code" || len(publicIDs(f)) > 0 || strings.HasPrefix(f.ID, "QRO-SCAN-") {
		return ""
	}
	id := f.Target.Identifier
	i := strings.LastIndexByte(id, ':')
	if i <= 0 || i == len(id)-1 {
		return ""
	}
	for _, c := range id[i+1:] {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return id
}

func enginesOf(f finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, e := range f.Evidence {
		if e.Type == EvidenceEngine {
			out[e.Data] = true
		}
	}
	return out
}

func sharesEngine(a, b finding.Finding) bool {
	eb := enginesOf(b)
	for e := range enginesOf(a) {
		if eb[e] {
			return true
		}
	}
	return false
}

// absorb garde a et y rattache ce que b apporte: ses moteurs, son titre, sa
// description, ses liens, ses references, et son extrait de code si a n'en a
// pas.
func absorb(a, b finding.Finding) finding.Finding {
	if d := strings.TrimSpace(b.Description); d != "" && !strings.Contains(a.Description, d) {
		if a.Description != "" {
			a.Description += "\n\n"
		}
		a.Description += d
	}
	a.Evidence = mergeEngines(a.Evidence, b.Evidence)
	engines := make([]string, 0, 2)
	for _, e := range b.Evidence {
		if e.Type == EvidenceEngine {
			engines = append(engines, e.Data)
		}
	}
	note := b.Title
	if len(engines) > 0 {
		note += " (" + strings.Join(engines, ", ") + ")"
	}
	a.Evidence = append(a.Evidence, finding.Evidence{Type: EvidenceMerged, Data: note})
	hasCode := false
	for _, e := range a.Evidence {
		if e.Type == "code" {
			hasCode = true
		}
	}
	urls := map[string]bool{}
	for _, e := range a.Evidence {
		if e.Type == "url" {
			urls[e.Data] = true
		}
	}
	for _, e := range b.Evidence {
		if e.Type == "url" && !urls[e.Data] {
			a.Evidence = append(a.Evidence, e)
			urls[e.Data] = true
			continue
		}
		if (e.Type == "code" && !hasCode) || e.Type == "rule" {
			a.Evidence = append(a.Evidence, e)
			if e.Type == "code" {
				hasCode = true
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range a.References {
		seen[r.Framework+"/"+r.ID] = true
	}
	for _, r := range b.References {
		if !seen[r.Framework+"/"+r.ID] {
			a.References = append(a.References, r)
			seen[r.Framework+"/"+r.ID] = true
		}
	}
	return a
}

// dedupe regroupe les constats qui decrivent la meme vulnerabilite connue,
// reconnue a un identifiant public partage (OSV, CVE ou GHSA). Deux moteurs qui
// tombent d'accord ne font pas deux failles: on garde le constat le plus
// informatif, et l'autre moteur s'ajoute a sa provenance.
//
// Les constats sans identifiant public (motifs de code, constats d'absence) ne
// sont jamais fusionnes. Partager une CWE ne suffit pas: deux injections au
// meme CWE dans deux fichiers restent deux constats.
func dedupe(fs []finding.Finding) []finding.Finding {
	var kept []finding.Finding
	index := map[string]int{} // identifiant public -> position dans kept

	for _, f := range fs {
		ids := publicIDs(f)
		pos := -1
		for _, id := range ids {
			if p, ok := index[id]; ok {
				pos = p
				break
			}
		}

		if pos < 0 {
			kept = append(kept, f)
			pos = len(kept) - 1
		} else if better(f, kept[pos]) {
			f.Evidence = mergeEngines(f.Evidence, kept[pos].Evidence)
			kept[pos] = f
		} else {
			kept[pos].Evidence = mergeEngines(kept[pos].Evidence, f.Evidence)
		}

		// Tous les identifiants des deux constats pointent vers le survivant,
		// pour qu'un troisieme moteur reconnu par un seul alias le rejoigne.
		for _, id := range ids {
			index[id] = pos
		}
		for _, id := range publicIDs(kept[pos]) {
			index[id] = pos
		}
	}
	return kept
}

// publicIDs rend les identifiants qui designent une vulnerabilite publiee.
func publicIDs(f finding.Finding) []string {
	var ids []string
	for _, r := range f.References {
		switch r.Framework {
		case "OSV", "CVE", "GHSA":
			if r.ID != "" {
				ids = append(ids, r.ID)
			}
		}
	}
	return ids
}

// better dit si a doit remplacer b: la gravite d'abord, puis le moteur le plus
// informatif.
func better(a, b finding.Finding) bool {
	if sa, sb := severityRank(a.Severity), severityRank(b.Severity); sa != sb {
		return sa > sb
	}
	return engineRank(a) > engineRank(b)
}

func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	default:
		return 0
	}
}

// engineRank rend la meilleure priorite parmi les moteurs cites en preuve.
func engineRank(f finding.Finding) int {
	best := 0
	for _, e := range f.Evidence {
		if e.Type == EvidenceEngine && enginePriority[e.Data] > best {
			best = enginePriority[e.Data]
		}
	}
	return best
}

// mergeEngines ajoute a dst les preuves de moteur et les etiquettes de pre-tri
// de src qu'il n'a pas deja.
func mergeEngines(dst, src []finding.Evidence) []finding.Evidence {
	// Les moteurs et les etiquettes de pre-tri passent au survivant: l'avis de
	// govulncheck sur l'appel du code fautif ne doit pas se perdre.
	keep := func(e finding.Evidence) bool { return e.Type == EvidenceEngine || e.Type == EvidenceContext }
	have := map[finding.Evidence]bool{}
	for _, e := range dst {
		if keep(e) {
			have[e] = true
		}
	}
	for _, e := range src {
		if keep(e) && !have[e] {
			dst = append(dst, e)
			have[e] = true
		}
	}
	return dst
}
