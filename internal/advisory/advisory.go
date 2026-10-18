// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package advisory prepare un brouillon de signalement prive a partir d'un
// constat de scan, dans la forme d'un GitHub Security Advisory.
//
// Le brouillon n'est pas un verdict. Il rassemble ce que le scan sait (ou,
// quelle regle, quelles references, quel commit) et laisse a remplir ce que
// seul l'operateur peut etablir: la confirmation sur une instance locale et
// l'impact reel. Quaero n'envoie rien. Le signalement se depose a la main, en
// prive, aupres du mainteneur, et rien n'est rendu public avant le correctif.
//
// Le corps est en anglais, la langue commune des mainteneurs. La liste de
// controle qui le precede, destinee a l'operateur, est en francais et doit
// etre retiree avant l'envoi.
package advisory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// metaPrefix marque les constats sur le scan lui-meme (moteur absent, en
// panne, rien a analyser). Ils ne decrivent aucune faille du depot.
const metaPrefix = "QRO-SCAN-"

// Candidates rend les constats qui peuvent devenir un signalement, pire
// d'abord: les constats de code et de dependances, pas ceux sur le scan.
func Candidates(rep *finding.Report) []finding.Finding {
	var out []finding.Finding
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, metaPrefix) || f.Status == finding.StatusPass {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Find rend le constat d'identifiant id, s'il peut devenir un signalement.
func Find(rep *finding.Report, id string) (finding.Finding, error) {
	for _, f := range Candidates(rep) {
		if f.ID == id {
			return f, nil
		}
	}
	if strings.HasPrefix(id, metaPrefix) {
		return finding.Finding{}, fmt.Errorf("%s decrit le scan lui-meme, pas une faille du depot", id)
	}
	return finding.Finding{}, fmt.Errorf("aucun constat %s dans ce rapport", id)
}

// Draft rend le brouillon Markdown du signalement de f, trouve dans rep.
func Draft(rep *finding.Report, f finding.Finding) string {
	var b strings.Builder
	target := contextString(rep, "cible")
	commit := contextString(rep, "commit")
	dependency := f.Target != nil && f.Target.Type == "dependency"

	writeChecklist(&b, f, dependency, publicIDs(f))

	fmt.Fprintf(&b, "# %s\n\n", f.Title)
	switch {
	case strings.HasPrefix(target, "github.com/"):
		fmt.Fprintf(&b, "**Repository:** %s  \n", target)
	case target != "":
		// Un dossier local: son chemin ne dit rien au mainteneur et decrit la
		// machine de l'operateur. Il ne part pas dans le brouillon.
		b.WriteString("**Repository:** TO COMPLETE (scanned from a local copy)  \n")
	}
	if commit != "" {
		fmt.Fprintf(&b, "**Analyzed revision:** `%s`  \n", commit)
	}
	if f.Target != nil && f.Target.Identifier != "" {
		label := "Location"
		if dependency {
			label = "Dependency"
		}
		fmt.Fprintf(&b, "**%s:** `%s`  \n", label, f.Target.Identifier)
	}
	if cwes := refsOf(f, "CWE"); len(cwes) > 0 {
		fmt.Fprintf(&b, "**Weakness:** %s  \n", strings.Join(cwes, ", "))
	}
	fmt.Fprintf(&b, "**Proposed severity:** %s (to be assessed with CVSS once confirmed)\n\n", severityWord(f.Severity))

	b.WriteString("## Summary\n\n")
	if dependency {
		fmt.Fprintf(&b, "The project depends on `%s`, which is affected by a published vulnerability (%s).\n\n",
			identifier(f), strings.Join(publicIDs(f), ", "))
	} else {
		fmt.Fprintf(&b, "Static analysis reports a potential weakness at `%s`. TO COMPLETE: one sentence on what is wrong, once confirmed.\n\n", identifier(f))
	}

	b.WriteString("## Details\n\n")
	if d := strings.TrimSpace(f.Description); d != "" {
		b.WriteString(d + "\n\n")
	}
	if code := evidence(f, "code"); len(code) > 0 {
		b.WriteString("Code at the reported location:\n\n```\n" + code[0] + "\n```\n\n")
	}
	if rules := evidence(f, "rule"); len(rules) > 0 {
		fmt.Fprintf(&b, "Rule: `%s`\n\n", rules[0])
	}
	if engines := evidence(f, "engine"); len(engines) > 0 {
		fmt.Fprintf(&b, "Reported by: %s.\n\n", strings.Join(engines, ", "))
	}
	for _, other := range evidence(f, "fusionne") {
		fmt.Fprintf(&b, "Also reported on the same line as: %s.\n\n", other)
	}

	b.WriteString("## Reproduction\n\n")
	b.WriteString("TO COMPLETE after confirming on a local instance you set up yourself: environment, steps, input, observed behaviour.\n\n")

	b.WriteString("## Impact\n\n")
	b.WriteString("TO COMPLETE: who is affected and what the confirmed weakness allows, as observed during confirmation.\n\n")

	b.WriteString("## Remediation\n\n")
	if dependency {
		if v := evidence(f, "version_cible"); len(v) > 0 {
			// La version vient du rapport, qui peut etre importe: elle ne doit
			// ni fermer le code en ligne ni ouvrir un lien.
			codes := make([]string, len(v))
			for i, x := range v {
				codes[i] = inlineCode(x)
			}
			fmt.Fprintf(&b, "Upgrade the dependency to %s or later, which fixes the vulnerability listed below.\n\n", strings.Join(codes, " or "))
			if cmds := evidence(f, "commande"); len(cmds) > 0 {
				b.WriteString("For example, from the repository root:\n\n" + fenced(strings.Join(cmds, "\n")))
			}
		} else {
			b.WriteString("Upgrade the dependency to a version that fixes the vulnerability listed below, or replace it.\n\n")
		}
	} else {
		b.WriteString("TO COMPLETE: the suggested fix. The rule description above usually states the expected safe pattern.\n\n")
		if fix := evidence(f, "correctif"); len(fix) > 0 {
			b.WriteString("The rule proposes this replacement for the reported line:\n\n" + fenced(fix[0]))
		}
	}

	if refs := references(f); len(refs) > 0 {
		b.WriteString("## References\n\n")
		for _, r := range refs {
			b.WriteString("- " + r + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Credits\n\n")
	b.WriteString("TO COMPLETE: reporter name.\n\n")
	fmt.Fprintf(&b, "<!-- Brouillon prepare par %s %s a partir du constat %s, run %s. -->\n",
		rep.Tool.Name, rep.Tool.Version, f.ID, rep.Run.ID)
	return b.String()
}

// inlineCode met un champ sur une ligne dans un code en ligne qu'il ne peut
// pas fermer.
func inlineCode(s string) string {
	return "`" + strings.ReplaceAll(strings.Join(strings.Fields(s), " "), "`", "'") + "`"
}

// fenced met du code dans un bloc que son contenu ne peut pas fermer.
func fenced(code string) string {
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
	return f + "\n" + strings.TrimRight(code, "\n") + "\n" + f + "\n\n"
}

// writeChecklist ecrit, en commentaire HTML, ce que l'operateur doit faire
// avant tout envoi. Un commentaire ne s'affiche pas si le brouillon est colle
// tel quel, mais il doit quand meme etre retire.
func writeChecklist(b *strings.Builder, f finding.Finding, dependency bool, public []string) {
	b.WriteString("<!--\n")
	b.WriteString("BROUILLON NON VERIFIE. A faire avant tout envoi, puis retirer ce bloc.\n\n")
	b.WriteString("- [ ] Confirmer la faille sur une instance locale montee soi-meme, jamais sur un systeme d'autrui.\n")
	b.WriteString("- [ ] Verifier qu'elle n'est pas deja connue: advisories et issues du depot, base CVE.\n")
	if dependency && len(public) > 0 {
		b.WriteString("- [ ] Vulnerabilite deja publique (" + strings.Join(public, ", ") + "): verifier que le projet est\n")
		b.WriteString("      reellement touche (code fautif appele). Sinon une mise a jour de dependance suffit,\n")
		b.WriteString("      par une PR ordinaire, sans signalement prive.\n")
	}
	b.WriteString("- [ ] Trouver le canal prive: onglet Security du depot (Report a vulnerability) ou SECURITY.md.\n")
	b.WriteString("- [ ] Ne rien publier (issue, PR, message) avant le correctif et la date convenue avec le mainteneur.\n")
	b.WriteString("- [ ] Remplir chaque section TO COMPLETE.\n")
	fmt.Fprintf(b, "\nConstat d'origine: %s (%s, %s).\n", f.ID, f.Severity, f.Status)
	b.WriteString("-->\n\n")
}

func contextString(rep *finding.Report, key string) string {
	if rep.Run.Context == nil {
		return ""
	}
	s, _ := rep.Run.Context[key].(string)
	return s
}

func identifier(f finding.Finding) string {
	if f.Target != nil && f.Target.Identifier != "" {
		return f.Target.Identifier
	}
	return f.ID
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

func refsOf(f finding.Finding, framework string) []string {
	var out []string
	for _, r := range f.References {
		if r.Framework == framework {
			out = append(out, r.ID)
		}
	}
	return out
}

// publicIDs rend les identifiants publics d'une vulnerabilite deja connue.
func publicIDs(f finding.Finding) []string {
	var out []string
	for _, r := range f.References {
		switch r.Framework {
		case "OSV", "CVE", "GHSA":
			out = append(out, r.ID)
		}
	}
	return out
}

// references rend chaque reference avec un lien vers sa fiche publique, puis
// les adresses fournies par les moteurs, sans doublon.
func references(f finding.Finding) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range f.References {
		add(referenceLink(r))
	}
	urls := evidence(f, "url")
	sort.Strings(urls)
	for _, u := range urls {
		add(u)
	}
	return out
}

func referenceLink(r finding.Reference) string {
	switch r.Framework {
	case "CWE":
		if n := strings.TrimPrefix(r.ID, "CWE-"); n != r.ID {
			return fmt.Sprintf("%s: https://cwe.mitre.org/data/definitions/%s.html", r.ID, n)
		}
	case "CVE":
		return fmt.Sprintf("%s: https://www.cve.org/CVERecord?id=%s", r.ID, r.ID)
	case "GHSA":
		return fmt.Sprintf("%s: https://github.com/advisories/%s", r.ID, r.ID)
	case "OSV":
		return fmt.Sprintf("%s: https://osv.dev/vulnerability/%s", r.ID, r.ID)
	}
	return r.ID
}

func severityWord(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "Critical"
	case finding.SeverityHigh:
		return "High"
	case finding.SeverityMedium:
		return "Medium"
	case finding.SeverityLow:
		return "Low"
	default:
		return "Informational"
	}
}
