// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package reports

import (
	"regexp"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/triage"
)

// Une analyse se compare a la precedente du meme depot, parmi les rapports
// enregistres: ce qui a ete corrige depuis, ce qui est nouveau. Un constat se
// reconnait d'une analyse a l'autre comme pour le tri, a sa regle, son
// fichier et le texte de sa ligne, pas a son numero, et une dependance a son
// paquet et a sa vulnerabilite. Rien n'est affirme pour un moteur qui n'a pas
// tourne entierement dans les deux analyses: un moteur absent ne corrige rien.

// Diff dit ce qui a change depuis l'analyse precedente du meme depot.
type Diff struct {
	// Previous nomme le rapport enregistre compare, "" s'il n'y en a pas.
	Previous string    `json:"rapport"`
	Since    time.Time `json:"depuis,omitzero"`
	Commit   string    `json:"commit,omitempty"`
	// Older dit que le rapport compare vient d'une version de Quaero qui
	// rangeait autrement les constats: quelques nouveautes ou corrections
	// peuvent n'en etre pas.
	Older bool `json:"version_anterieure,omitempty"`
	// New liste les constats de l'analyse absents de la precedente.
	New []string `json:"nouveaux"`
	// Fixed decrit les constats de la precedente absents de l'analyse.
	Fixed     []Gone `json:"corriges"`
	Unchanged int    `json:"inchanges"`
	// Uncompared compte les constats qu'un moteur n'a pas pu revoir, Engines
	// nomme ces moteurs.
	Uncompared int      `json:"non_compares,omitempty"`
	Engines    []string `json:"moteurs_non_compares,omitempty"`
}

// Gone decrit un constat de l'analyse precedente qui n'est plus releve.
type Gone struct {
	ID         string           `json:"id"`
	Title      string           `json:"titre"`
	Where      string           `json:"lieu,omitempty"`
	Severity   finding.Severity `json:"gravite"`
	Dependency bool             `json:"dependance,omitempty"`
	Refs       []string         `json:"references,omitempty"`
}

// findingsFormat est la forme des constats des rapports d'aujourd'hui (voir
// codescan.FindingsFormat). Un rapport sans ce numero est d'avant.
const findingsFormat = 2

// DiffWith compare cur a l'analyse enregistree juste avant, du meme depot.
// Sans analyse precedente, le Diff rendu ne nomme aucun rapport.
func (s *Store) DiffWith(cur *finding.Report) *Diff {
	if s == nil || cur == nil {
		return nil
	}
	id, prev := s.Previous(cur)
	if prev == nil {
		return &Diff{New: []string{}, Fixed: []Gone{}}
	}
	return Compare(id, prev, cur)
}

// Previous rend le rapport enregistre du meme depot, analyse juste avant cur,
// et son identifiant, ou nil. Les rapports se datent comme dans la liste: la
// fin de l'analyse, sans depasser le moment ou ils ont ete ranges, pour
// qu'un rapport venu d'une machine a l'horloge en avance ne passe pas pour
// plus recent. Pour un dossier local, seul un rapport de la meme machine
// compte: le meme chemin ailleurs n'est pas le meme depot.
func (s *Store) Previous(cur *finding.Report) (string, *finding.Report) {
	key := triage.TargetKey(cur)
	if key == "" {
		return "", nil
	}
	local := !strings.HasPrefix(key, "github.com/")
	when := runDate(cur)
	if when.IsZero() {
		when = time.Now()
	}
	list, err := s.List()
	if err != nil {
		return "", nil
	}
	// Un rapport rouvert se date comme les autres rapports de la liste.
	for _, e := range list {
		if c, ok := s.summary(e.ID); ok && cur.Run.ID != "" && c.run == cur.Run.ID {
			when = sortKey(e)
		}
	}
	// La liste va de la plus recente a la plus ancienne.
	for _, e := range list {
		if !sortKey(e).Before(when) || triage.TargetKey(labelOnly(e.Target)) != key {
			continue
		}
		rep, err := s.Load(e.ID)
		if err != nil || rep.Run.ID == cur.Run.ID || (local && !sameMachine(rep, cur)) {
			continue
		}
		return e.ID, rep
	}
	return "", nil
}

// sameMachine dit si deux rapports viennent de la meme machine: par l'identifiant
// que Quaero y garde (contexte « poste »), sinon par le nom de la machine, sans
// tenir compte de la casse. Le nom seul peut changer avec le reseau.
func sameMachine(a, b *finding.Report) bool {
	pa, _ := a.Run.Context["poste"].(string)
	pb, _ := b.Run.Context["poste"].(string)
	if pa != "" && pb != "" {
		return pa == pb
	}
	return strings.EqualFold(a.Run.Host, b.Run.Host)
}

// Compare dit ce qui a change de prev a cur. Les constats s'apparient un a
// un: par empreinte d'abord, comme pour le tri, puis, pour ce qui reste, par
// endroit et regle commune, pour qu'un changement de titre ou de moteur
// retenu a la fusion ne passe ni pour une correction ni pour une nouveaute.
// Un constat nouveau doit avoir pu etre vu: l'un de ses moteurs a tourne
// entierement dans l'analyse precedente. Un constat corrige aussi, par tous
// ses moteurs: celui qui manque l'aurait peut-etre releve.
func Compare(prevID string, prev, cur *finding.Report) *Diff {
	d := &Diff{Previous: prevID, Since: runDate(prev), New: []string{}, Fixed: []Gone{}}
	d.Commit, _ = prev.Run.Context["commit"].(string)
	d.Older = format(prev) < format(cur)
	prevOK, curOK := complete(prev), complete(cur)
	curPartial := partial(cur)
	prevList, curList := advisory.Candidates(prev), advisory.Candidates(cur)
	prevFP, curFP := triage.Fingerprints(prev), triage.Fingerprints(cur)

	// Empreintes: chacune s'apparie une fois.
	pairedPrev := make([]bool, len(prevList))
	pairedCur := make([]bool, len(curList))
	byPrint := map[string][]int{}
	for i, f := range prevList {
		byPrint[prevFP[f.ID]] = append(byPrint[prevFP[f.ID]], i)
	}
	for j, f := range curList {
		if is := byPrint[curFP[f.ID]]; len(is) > 0 {
			pairedPrev[is[0]], pairedCur[j] = true, true
			byPrint[curFP[f.ID]] = is[1:]
		}
	}
	// Puis le meme endroit avec une regle commune, ou le meme paquet avec un
	// identifiant public commun. Chaque constat est decrit une fois, et les
	// anciens sont ranges par endroit et par paquet: la comparaison reste
	// lineaire, meme pour des milliers de constats.
	prevKeys, curKeys := keysOf(prevList), keysOf(curList)
	buckets := map[string][]int{}
	for i, k := range prevKeys {
		if pairedPrev[i] {
			continue
		}
		for _, b := range k.buckets {
			buckets[b] = append(buckets[b], i)
		}
	}
	for j, k := range curKeys {
		if pairedCur[j] {
			continue
		}
	search:
		for _, b := range k.buckets {
			// Les anciens deja apparies sortent du casier: une ligne repetee
			// mille fois ne se parcourt pas mille fois.
			for len(buckets[b]) > 0 && pairedPrev[buckets[b][0]] {
				buckets[b] = buckets[b][1:]
			}
			for _, i := range buckets[b] {
				if !pairedPrev[i] && k.matches(prevKeys[i]) {
					pairedPrev[i], pairedCur[j] = true, true
					break search
				}
			}
		}
	}
	// Un rapport d'avant rangeait sous un seul constat une CVE qui touchait
	// plusieurs paquets (x/net et stdlib): un paquet qui la porte n'y est pas
	// nouveau si le rapport la portait deja, sous un autre nom.
	var oldIDs map[string]bool
	if d.Older {
		oldIDs = map[string]bool{}
		for _, p := range prevList {
			for _, id := range publicIDs(p) {
				oldIDs[id] = true
			}
		}
	}

	missing := map[string]bool{}
	note := func(f finding.Finding, ok map[string]bool) {
		d.Uncompared++
		for _, e := range engines(f) {
			if !ok[e] && !missing[e] {
				missing[e] = true
				d.Engines = append(d.Engines, e)
			}
		}
	}
	for j, f := range curList {
		switch {
		case pairedCur[j] || anyIn(publicIDs(f), oldIDs):
			d.Unchanged++
		case seenBy(f, prevOK):
			d.New = append(d.New, f.ID)
		default:
			note(f, prevOK)
		}
	}
	for i, f := range prevList {
		switch {
		case pairedPrev[i]:
		case fixedFor(f, curOK, curPartial):
			g := Gone{ID: f.ID, Title: f.Title, Severity: f.Severity, Dependency: published(f), Refs: publicIDs(f)}
			if f.Target != nil {
				g.Where = f.Target.Identifier
			}
			d.Fixed = append(d.Fixed, g)
		default:
			note(f, curOK)
		}
	}
	return d
}

// matchKey decrit un constat pour l'appariement large: le meme endroit avec
// une regle commune, ou le meme paquet sous un identifiant public commun.
type matchKey struct {
	dep     bool
	rules   map[string]bool
	ids     map[string]bool
	buckets []string // endroit, ou paquet et identifiant
}

func keysOf(list []finding.Finding) []matchKey {
	out := make([]matchKey, len(list))
	for i, f := range list {
		k := matchKey{dep: published(f)}
		if k.dep {
			name, _ := depName(f)
			ids := publicIDs(f)
			k.ids = set(ids)
			for _, id := range ids {
				k.buckets = append(k.buckets, "dep\x00"+strings.ToLower(name)+"\x00"+id)
			}
		} else if p := triage.Place(f); p != "" {
			k.rules = set(rules(f))
			k.buckets = []string{"code\x00" + p}
		}
		out[i] = k
	}
	return out
}

// matches dit si deux constats ranges dans le meme casier parlent de la meme
// chose. Un paquet y est deja range avec un identifiant commun; une ligne doit
// encore partager une regle.
func (k matchKey) matches(o matchKey) bool {
	if k.dep != o.dep {
		return false
	}
	if k.dep {
		return true
	}
	for r := range k.rules {
		if o.rules[r] {
			return true
		}
	}
	return false
}

// rules rend les regles qui ont releve un constat de code: celles de semgrep,
// et celles de gosec, dans le titre ou dans ce qui y a ete fusionne.
func rules(f finding.Finding) []string {
	out := evidence(f, "rule")
	for _, t := range append([]string{f.Title}, evidence(f, "fusionne")...) {
		if r, _, ok := strings.Cut(t, ":"); ok && gosecRule.MatchString(r) {
			out = append(out, r)
		}
	}
	return out
}

var gosecRule = regexp.MustCompile(`^G[0-9]{3}$`)

// publicIDs rend les identifiants publics d'un constat (OSV, GHSA, CVE), sans
// les CWE.
func publicIDs(f finding.Finding) []string {
	var out []string
	for _, r := range f.References {
		if (r.Framework == "OSV" || r.Framework == "GHSA" || r.Framework == "CVE") && r.ID != "" && !contains(out, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out
}

func set(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

func anyIn(items []string, in map[string]bool) bool {
	for _, s := range items {
		if in[s] {
			return true
		}
	}
	return false
}

// format rend la forme des constats d'un rapport, 0 pour un rapport d'avant.
func format(rep *finding.Report) int {
	switch v := rep.Run.Context["format_constats"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// complete rend les moteurs qui ont tourne entierement: lances, sans echec,
// sans analyse partielle, avec quelque chose a lire.
func complete(rep *finding.Report) map[string]bool {
	ok := map[string]bool{}
	switch ran := rep.Run.Context["scanners"].(type) {
	case []string:
		for _, n := range ran {
			ok[n] = true
		}
	case []any:
		for _, n := range ran {
			if name, _ := n.(string); name != "" {
				ok[name] = true
			}
		}
	}
	for _, f := range rep.Findings {
		for _, prefix := range []string{"QRO-SCAN-ABSENT-", "QRO-SCAN-ERREUR-", "QRO-SCAN-PARTIEL-", "QRO-SCAN-VIDE-"} {
			if name, found := strings.CutPrefix(f.ID, prefix); found {
				delete(ok, name)
			}
		}
	}
	return ok
}

// seenBy dit si l'autre analyse a pu relever f: l'un de ses moteurs y a
// tourne entierement. Un constat sans moteur nomme vient d'un rapport ancien,
// il est compare.
func seenBy(f finding.Finding, ok map[string]bool) bool {
	eng := engines(f)
	if len(eng) == 0 {
		return true
	}
	for _, e := range eng {
		if ok[e] {
			return true
		}
	}
	return false
}

// fixedFor dit si l'analyse du jour a pu revoir f, pour le dire corrige: tous
// ses moteurs ont tourne, entierement, ou en partie quand un autre l'a fait
// entierement. govulncheck est souvent en partie pour toujours, sur un outil
// qui ne se compile pas pour tous les systemes, et osv-scanner lit les memes
// go.mod: une dependance mise a jour se dit corrigee quand meme. Un constat
// que seuls des moteurs en partie relevaient reste non compare.
func fixedFor(f finding.Finding, ok, part map[string]bool) bool {
	eng := engines(f)
	if len(eng) == 0 {
		return true
	}
	full := false
	for _, e := range eng {
		switch {
		case ok[e]:
			full = true
		case !part[e]:
			return false
		}
	}
	return full
}

// partial rend les moteurs qui n'ont tourne qu'en partie.
func partial(rep *finding.Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range rep.Findings {
		if name, found := strings.CutPrefix(f.ID, "QRO-SCAN-PARTIEL-"); found {
			out[name] = true
		}
	}
	return out
}

func engines(f finding.Finding) []string { return evidence(f, "engine") }

func runDate(rep *finding.Report) time.Time {
	if !rep.Run.FinishedAt.IsZero() {
		return rep.Run.FinishedAt
	}
	return rep.Run.StartedAt
}

// labelOnly fait d'une cible un rapport, pour en tirer la cle du depot.
func labelOnly(label string) *finding.Report {
	return &finding.Report{Run: finding.Run{Context: map[string]any{"cible": label}}}
}
