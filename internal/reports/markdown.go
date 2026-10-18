// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package reports

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/triage"
)

// Markdown met un rapport en texte lisible sans Quaero: dans un editeur de
// texte tel quel, ou mis en forme par n'importe quel lecteur Markdown. Il range
// les constats comme la page: a verifier d'abord, puis les dependances, puis
// les sections repliees. decisions porte le tri deja fait, par constat, et
// peut etre nil.
//
// Le texte vient du rapport, qui peut avoir ete importe: rien n'y est
// interprete, les champs sont recopies sur une ligne et les blocs de code sont
// clos par une cloture plus longue que ce qu'ils contiennent.
func Markdown(rep *finding.Report, decisions map[string]triage.Decision, now time.Time) string {
	var b strings.Builder
	e := entryOf("", rep)
	fmt.Fprintf(&b, "# Rapport Quaero, %s\n\n", text(shortTarget(e.Target)))
	head := "Analyse de " + code(e.Target)
	if e.Commit != "" {
		head += ", commit " + line(short(e.Commit, 7))
	}
	if !e.Date.IsZero() {
		head += ", le " + e.Date.Local().Format("02/01/2006 à 15h04")
	}
	if e.Seconds > 0 {
		head += ", " + seconds(e.Seconds)
	}
	b.WriteString(head + ".\n\n")

	list := advisory.Candidates(rep)
	// Une dependance se range a part si toutes ses vulnerabilites sont sur un
	// module que rien n'importe, comme dans la page.
	unusedDep := map[string]bool{}
	for _, f := range list {
		if !published(f) {
			continue
		}
		name, _ := depName(f)
		all, seen := unusedDep[name]
		unusedDep[name] = (all || !seen) && contexts(f)["inutilise"]
	}
	var main, deps, essais, tiers, unused, faux []finding.Finding
	for _, f := range list {
		ctx := contexts(f)
		name, _ := depName(f)
		switch {
		case published(f) && unusedDep[name]:
			unused = append(unused, f)
		case published(f):
			deps = append(deps, f)
		case decisions[f.ID].State == triage.FalsePositive:
			faux = append(faux, f)
		case ctx["genere"]:
			tiers = append(tiers, f)
		case ctx["test"] || ctx["exemple"]:
			essais = append(essais, f)
		default:
			main = append(main, f)
		}
	}

	b.WriteString("## Résumé\n\n")
	b.WriteString(summary(list) + "\n\n")
	if eng := enginesLine(rep); eng != "" {
		b.WriteString(eng + "\n\n")
	}

	section := func(title, hint string, fs []finding.Finding, dep bool) {
		if len(fs) == 0 {
			return
		}
		// Le plus grave d'abord, dans l'ordre du rapport a gravite egale.
		sort.SliceStable(fs, func(i, j int) bool { return rank(fs[i].Severity) > rank(fs[j].Severity) })
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, count(fs, dep))
		if hint != "" {
			b.WriteString(hint + "\n\n")
		}
		if dep {
			writeDeps(&b, fs, rep)
		} else {
			writeGroups(&b, fs, decisions)
		}
	}
	section("À vérifier", "", main, false)
	section("Dépendances", "Vulnérabilités déjà publiées. Une mise à jour de la dépendance, par une PR ordinaire, suffit.", deps, true)
	section("Tests et exemples", "Hors du logiciel livré, à regarder en dernier.", essais, false)
	section("Code tiers ou généré", "Livré, mais corrigé en amont ou par une nouvelle génération.", tiers, false)
	section("Dépendances inutilisées", "Requises par go.mod, importées par aucun paquet. go mod tidy les retire.", unused, true)
	section("Faux positifs", "Écartés à la main.", faux, false)

	fmt.Fprintf(&b, "---\n\nÀ vérifier à la main. Un constat non confirmé ne se signale pas.\nExporté par Quaero %s le %s.\n",
		line(rep.Tool.Version), now.Local().Format("02/01/2006 à 15h04"))
	return b.String()
}

// shortTarget rend le nom lisible d'une cible: owner/repo pour un depot GitHub,
// le dernier dossier pour un chemin.
func shortTarget(target string) string {
	t := strings.TrimSpace(target)
	if rest, ok := cutPrefixFold(t, "github.com/"); ok {
		return strings.Trim(rest, "/")
	}
	parts := strings.FieldsFunc(t, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return "rapport"
	}
	return parts[len(parts)-1]
}

// ExportName rend le nom du fichier Markdown d'un rapport: le nom court de la
// cible et la date de l'analyse.
func ExportName(rep *finding.Report) string {
	e := entryOf("", rep)
	name := Slug(e.Target)
	if !e.Date.IsZero() {
		name += "_" + e.Date.Local().Format("2006-01-02_15h04")
	}
	return name + ".md"
}

var severityWords = map[finding.Severity]string{
	finding.SeverityCritical: "critique",
	finding.SeverityHigh:     "élevée",
	finding.SeverityMedium:   "moyenne",
	finding.SeverityLow:      "faible",
	finding.SeverityInfo:     "info",
}

var stateWords = map[triage.State]string{
	triage.Confirmed:     "confirmé",
	triage.Reported:      "signalé",
	triage.FalsePositive: "faux positif",
}

var contextWords = map[string]string{
	"test": "test", "exemple": "exemple", "genere": "généré ou tiers", "ci": "CI",
	"appele": "code fautif appelé", "non_appele": "code fautif non appelé", "inutilise": "inutilisée",
}

// writeGroups ecrit les constats de code regroupes par regle: la description
// une fois, puis chaque endroit avec son extrait et son tri. Neuf appels
// signales par la meme regle se lisent en un seul bloc.
func writeGroups(b *strings.Builder, fs []finding.Finding, decisions map[string]triage.Decision) {
	var order []string
	groups := map[string][]finding.Finding{}
	for _, f := range fs {
		if _, ok := groups[f.Title]; !ok {
			order = append(order, f.Title)
		}
		groups[f.Title] = append(groups[f.Title], f)
	}
	for _, title := range order {
		g := groups[title]
		first := g[0]
		sev := severityWords[first.Severity]
		if sev == "" {
			sev = string(first.Severity)
		}
		head := fmt.Sprintf("### [%s] %s", strings.ToUpper(sev), text(title))
		if len(g) > 1 {
			head = strings.TrimRight(head, ". ") + fmt.Sprintf(", %d endroits", len(g))
		}
		b.WriteString(head + "\n\n")
		if first.Description != "" && first.Description != first.Title {
			b.WriteString(text(first.Description) + "\n\n")
		}
		var about []string
		if rule := evidence(first, "rule"); len(rule) > 0 {
			about = append(about, "Règle "+code(rule[0]))
		}
		var refs []string
		for _, f := range g {
			for _, id := range refIDs(f) {
				if !contains(refs, id) {
					refs = append(refs, id)
				}
			}
		}
		if len(refs) > 0 {
			about = append(about, "références "+text(strings.Join(refs, ", ")))
		}
		if len(about) > 0 {
			line := strings.Join(about, ", ")
			b.WriteString(strings.ToUpper(line[:1]) + line[1:] + ".\n\n")
		}
		for _, f := range g {
			writePlace(b, f, decisions[f.ID])
		}
		b.WriteString("\n")
		if first.Remediation != "" {
			b.WriteString(text(first.Remediation) + "\n\n")
		}
	}
}

// writePlace ecrit un endroit signale: le fichier et la ligne, les moteurs,
// les etiquettes du pre-tri, le tri decide et l'extrait de code.
func writePlace(b *strings.Builder, f finding.Finding, d triage.Decision) {
	var where []string
	if f.Target != nil && f.Target.Identifier != "" {
		where = append(where, code(f.Target.Identifier))
	}
	if eng := evidence(f, "engine"); len(eng) > 0 {
		where = append(where, text(strings.Join(eng, ", ")))
	}
	for _, c := range evidence(f, "contexte") {
		if w := contextWords[c]; w != "" {
			where = append(where, w)
		}
	}
	if len(where) == 0 {
		where = append(where, text(f.ID))
	}
	item := "- " + strings.Join(where, ", ")
	if w := stateWords[d.State]; w != "" {
		item += ". " + strings.ToUpper(w[:1]) + w[1:]
		if d.Note != "" {
			item += ", " + text(d.Note)
		}
	}
	b.WriteString(item + "\n")
	if snippet := evidence(f, "code"); len(snippet) > 0 {
		for _, l := range strings.Split(strings.TrimRight(fence(snippet[0]), "\n"), "\n") {
			b.WriteString("  " + l + "\n")
		}
	}
}

// writeDeps regroupe les vulnerabilites publiees par dependance, comme la page.
func writeDeps(b *strings.Builder, fs []finding.Finding, rep *finding.Report) {
	type group struct {
		name     string
		versions []string
		list     []finding.Finding
	}
	var order []*group
	byName := map[string]*group{}
	for _, f := range fs {
		name, version := depName(f)
		g := byName[name]
		if g == nil {
			g = &group{name: name}
			byName[name] = g
			order = append(order, g)
		}
		if version != "" && !contains(g.versions, version) {
			g.versions = append(g.versions, version)
		}
		g.list = append(g.list, f)
	}
	goVersion, _ := rep.Run.Context["go_compile"].(string)
	for _, g := range order {
		n := len(g.list)
		plural := "s publiées"
		if n == 1 {
			plural = " publiée"
		}
		title := text(g.name)
		if len(g.versions) > 0 {
			title += " " + text(strings.Join(g.versions, ", "))
		}
		fmt.Fprintf(b, "### %s, %d vulnérabilité%s\n\n", title, n, plural)
		called, notCalled := false, false
		for _, f := range g.list {
			ctx := contexts(f)
			called = called || ctx["appele"]
			notCalled = notCalled || ctx["non_appele"]
			sev := severityWords[f.Severity]
			ids := refIDs(f)
			item := "- [" + sev + "] " + text(f.Title)
			if len(ids) > 0 {
				item += " (" + text(strings.Join(ids[:min(3, len(ids))], ", ")) + ")"
			}
			b.WriteString(item + "\n")
		}
		b.WriteString("\n")
		switch {
		case called:
			b.WriteString("govulncheck trouve un appel au code fautif. Vérifier l'impact, puis proposer la mise à jour.\n\n")
		case notCalled:
			b.WriteString("govulncheck ne trouve aucun appel au code fautif. La mise à jour reste à faire, sans urgence.\n\n")
		}
		if g.name == "stdlib" {
			s := "osv-scanner lit la version de Go écrite dans go.mod, pas celle qui compile."
			if goVersion != "" {
				s += " govulncheck a compilé avec " + text(goVersion) + "."
			}
			b.WriteString(s + "\n\n")
		}
	}
}

// summary compte comme la page: un element par constat de code, un par
// dependance.
func summary(list []finding.Finding) string {
	n := shownCount(list)
	if n == 0 {
		return "Rien relevé par les moteurs."
	}
	worst := map[string]finding.Severity{}
	var keys []string
	code := 0
	for _, f := range list {
		key := f.ID
		if published(f) {
			key, _ = depName(f)
			key = "dep:" + key
		} else {
			code++
		}
		prev, seen := worst[key]
		if !seen {
			keys = append(keys, key)
		}
		if !seen || rank(f.Severity) > rank(prev) {
			worst[key] = f.Severity
		}
	}
	bySev := map[finding.Severity]int{}
	for _, k := range keys {
		bySev[worst[k]]++
	}
	var parts []string
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if c := bySev[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", severityWords[sev], c))
		}
	}
	return plural(n, "constat", "constats") + ". Gravité " + strings.Join(parts, ", ") +
		fmt.Sprintf(". %d dans le code, %d %s.", code, n-code, map[bool]string{true: "dépendance", false: "dépendances"}[n-code == 1])
}

// enginesLine dit ce que chaque moteur a fait.
func enginesLine(rep *finding.Report) string {
	durations, _ := rep.Run.Context["durees_s"].(map[string]any)
	ran, _ := rep.Run.Context["scanners"].([]any)
	state := map[string]string{}
	for _, f := range rep.Findings {
		for prefix, word := range map[string]string{
			"QRO-SCAN-ABSENT-": "absent", "QRO-SCAN-ERREUR-": "en échec",
			"QRO-SCAN-VIDE-": "rien à lire", "QRO-SCAN-PARTIEL-": "en partie",
		} {
			if name, ok := strings.CutPrefix(f.ID, prefix); ok {
				state[name] = word
				if f.Observed != "" && word != "absent" {
					state[name] += ", " + line(f.Observed)
				}
			}
		}
	}
	var parts []string
	seen := map[string]bool{}
	for _, r := range ran {
		name, _ := r.(string)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		part := line(name)
		if d, ok := durations[name].(float64); ok {
			part += " " + seconds(d)
		}
		if st := state[name]; st != "" {
			part += " (" + st + ")"
		}
		parts = append(parts, part)
	}
	var rest []string
	for name, st := range state {
		if !seen[name] {
			rest = append(rest, line(name)+" ("+st+")")
		}
	}
	sort.Strings(rest)
	parts = append(parts, rest...)
	if len(parts) == 0 {
		return ""
	}
	return "Moteurs, " + strings.Join(parts, ", ") + "."
}

func count(fs []finding.Finding, dep bool) int {
	if !dep {
		return len(fs)
	}
	return shownCount(fs)
}

func depName(f finding.Finding) (string, string) {
	id := "?"
	if f.Target != nil && f.Target.Identifier != "" {
		id = f.Target.Identifier
	}
	at := strings.LastIndex(id, "@")
	if at <= 0 {
		return id, ""
	}
	v := id[at+1:]
	for _, p := range []string{"go", "v"} {
		if strings.HasPrefix(v, p) && len(v) > len(p) && v[len(p)] >= '0' && v[len(p)] <= '9' {
			v = v[len(p):]
		}
	}
	return id[:at], v
}

func contexts(f finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, c := range evidence(f, "contexte") {
		out[c] = true
	}
	return out
}

func evidence(f finding.Finding, kind string) []string {
	var out []string
	for _, e := range f.Evidence {
		if e.Type == kind && strings.TrimSpace(e.Data) != "" {
			out = append(out, strings.TrimSpace(e.Data))
		}
	}
	return out
}

func refIDs(f finding.Finding) []string {
	var out []string
	for _, r := range f.References {
		if r.ID != "" && !contains(out, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out
}

func rank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	}
	return 0
}

// line ramene un champ sur une ligne: un retour a la ligne venu d'un rapport
// ne doit pas ouvrir un titre ou une liste dans le Markdown.
func line(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// text prepare un champ du rapport pour un paragraphe: sur une ligne, sans
// balise ni lien que lirait un afficheur Markdown, sans titre ni liste en tete.
func text(s string) string {
	s = strings.NewReplacer("<", `\<`, "[", `\[`).Replace(line(s))
	if s != "" && strings.ContainsRune("#>-+*|=`", rune(s[0])) {
		s = `\` + s
	}
	return s
}

// code met un champ dans un bout de code en ligne, qu'il ne peut pas fermer.
func code(s string) string {
	return "`" + strings.ReplaceAll(line(s), "`", "'") + "`"
}

// fence met du code dans un bloc dont la cloture est plus longue que toute
// suite de backticks qu'il contient: le code ne peut pas fermer le bloc.
func fence(code string) string {
	longest, run := 0, 0
	for _, r := range code {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	f := strings.Repeat("`", max(3, longest+1))
	return f + "\n" + strings.TrimRight(strings.ReplaceAll(code, "\r\n", "\n"), "\n") + "\n" + f + "\n\n"
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func seconds(s float64) string {
	if s < 60 {
		out := strings.Replace(fmt.Sprintf("%.1f", math.Round(s*10)/10), ".", ",", 1)
		return strings.TrimSuffix(out, ",0") + " s"
	}
	return fmt.Sprintf("%d min %02d s", int(s)/60, int(s)%60)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
