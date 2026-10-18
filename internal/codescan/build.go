// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// osv-scanner lit le go.mod tel qu'il est ecrit. Un module peut y rester apres
// que le code a cesse de s'en servir, et osv-scanner en rapporte alors toutes
// les vulnerabilites. Deux commandes du go, qui raisonnent sur tous les tags de
// build, tests compris, quels que soient le systeme et cgo, disent s'il sert
// encore. Le constat d'osv-scanner recoit alors l'etiquette « inutilise » et se
// range a part. Il reste dans le rapport, avec sa gravite.
//
//   - go mod tidy -diff charge tout le graphe des paquets et echoue au moindre
//     module introuvable. Il dit quels modules il retirerait de go.mod.
//   - go mod why -m confirme, pour chacun, qu'aucun paquet n'en a besoin.
//
// go mod why seul ne suffit pas: un module qu'il ne peut pas telecharger, il le
// dit inutile sans erreur. tidy -diff seul non plus: pour un ancien go.mod, un
// module retire peut rester dans le graphe. Un module n'est inutile que si les
// deux le disent. Ni l'un ni l'autre n'execute de code du depot, et aucun
// n'ecrit go.mod ou go.sum.

// maxGoModBytes borne la lecture d'un go.mod. Au-dela, rien n'est etiquete.
const maxGoModBytes = 1 << 20

// whyBatch borne le nombre de modules par appel, pour rester sous la longueur
// maximale d'une ligne de commande Windows.
const whyBatch = 200

// unusedModules rend les modules requis par le go.mod de dir qu'aucun paquet du
// module n'importe. Il rend nil des que la reponse n'est pas sure: go absent ou
// trop ancien, go.mod illisible, module vendorise, module introuvable, commande
// en echec ou module sans reponse.
func unusedModules(ctx context.Context, dir string) map[string]bool {
	// Un depot vendorise se compile sans telecharger: les deux commandes, elles,
	// telechargeraient des modules que l'analyse n'a jamais demandes.
	if _, err := os.Lstat(filepath.Join(dir, "vendor", "modules.txt")); err == nil {
		return nil
	}
	data, ok := readRepoHead(dir, "go.mod", maxGoModBytes+1)
	if !ok || len(data) > maxGoModBytes {
		return nil
	}
	required := map[string]bool{}
	for _, m := range requiredModules(string(data)) {
		required[m] = true
	}
	bin, err := resolveBin("go")
	if err != nil {
		return nil
	}
	res, err := runTool(ctx, bin, dir, "mod", "tidy", "-diff")
	if err != nil {
		return nil
	}
	// 0: go.mod deja propre. 1 avec un diff: tidy a tout charge et retirerait
	// des lignes. 1 sans diff: une erreur, le graphe ne s'est pas charge.
	var candidates []string
	switch {
	case res.exitCode == 0:
		return map[string]bool{}
	case res.exitCode == 1 && strings.Contains(string(res.stdout), "--- current/go."):
		for m := range parseTidyDiff(string(res.stdout)) {
			if required[m] {
				candidates = append(candidates, m)
			}
		}
	default:
		return nil
	}
	sort.Strings(candidates)
	out := map[string]bool{}
	for start := 0; start < len(candidates); start += whyBatch {
		batch := candidates[start:min(start+whyBatch, len(candidates))]
		res, err := runTool(ctx, bin, dir, append([]string{"mod", "why", "-m"}, batch...)...)
		if err != nil || res.accept(0) != nil {
			return nil
		}
		answers := parseWhy(string(res.stdout))
		for _, m := range batch {
			unused, known := answers[m]
			if !known {
				return nil
			}
			if unused {
				out[m] = true
			}
		}
	}
	return out
}

// goModDirectives sont les mots qui ouvrent une directive de go.mod autre que
// require: une ligne qui en commence une ne nomme pas un module requis.
var goModDirectives = set("module", "go", "toolchain", "replace", "exclude", "retract", "godebug", "tool", "ignore")

// parseTidyDiff rend les modules que go mod tidy -diff retire des lignes
// require de go.mod sans les remettre ailleurs. Un module deplace d'un bloc a
// l'autre, ou change de version, n'est pas retire.
func parseTidyDiff(out string) map[string]bool {
	removed, added := map[string]bool{}, map[string]bool{}
	inGoMod := false
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "--- "):
			inGoMod = strings.HasSuffix(strings.TrimSpace(line), "/go.mod")
			continue
		case strings.HasPrefix(line, "+++ "), strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "diff "):
			continue
		}
		if !inGoMod || line == "" || (line[0] != '-' && line[0] != '+') {
			continue
		}
		body := line[1:]
		if i := strings.Index(body, "//"); i >= 0 {
			body = body[:i]
		}
		if strings.Contains(body, "=>") {
			continue
		}
		fields := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(body))
		if len(fields) > 0 && fields[0] == "require" {
			fields = fields[1:]
		}
		if len(fields) < 2 || fields[0] == "(" || fields[0] == ")" || goModDirectives[fields[0]] {
			continue
		}
		if line[0] == '-' {
			removed[unquote(fields[0])] = true
		} else {
			added[unquote(fields[0])] = true
		}
	}
	for m := range added {
		delete(removed, m)
	}
	return removed
}

// requiredModules lit les directives require de go.mod, en ligne ou en bloc.
func requiredModules(text string) []string {
	var out []string
	inBlock := false
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		// « require( » s'ecrit aussi sans espace: les parentheses deviennent
		// des mots a part. Un chemin de module n'en contient pas.
		line = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(line)
		fields := strings.Fields(line)
		if !inBlock {
			if len(fields) < 2 || fields[0] != "require" {
				continue
			}
			if fields[1] != "(" {
				out = append(out, unquote(fields[1]))
				continue
			}
			inBlock, fields = true, fields[2:]
		}
		if len(fields) == 0 {
			continue
		}
		if fields[0] == ")" {
			inBlock = false
			continue
		}
		out = append(out, unquote(fields[0]))
		if fields[len(fields)-1] == ")" {
			inBlock = false
		}
	}
	return out
}

func unquote(s string) string {
	return strings.Trim(s, "\"`")
}

// parseWhy lit la sortie de go mod why -m: un bloc « # module » par module,
// suivi du chemin d'import qui l'amene, ou de « (main module does not need
// module ...) ». La reponse vaut true pour un module dont rien n'a besoin.
func parseWhy(out string) map[string]bool {
	answers := map[string]bool{}
	cur := ""
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "# "):
			cur = strings.TrimSpace(line[2:])
			answers[cur] = false
		case cur != "" && strings.HasPrefix(line, "(main module does not need"):
			answers[cur] = true
		}
	}
	return answers
}

// unusedIDs rend les identifiants publics dont tous les constats, avant fusion,
// portent sur une dependance inutilisee d'un go.mod du depot. unused porte, par
// go.mod, les modules que rien n'importe. dedupe regroupe les
// constats qui partagent un identifiant, de proche en proche, sans garder leur
// manifeste ni leur module: une vulnerabilite qui touche aussi stdlib, un autre
// go.mod ou un module compile ne doit pas se ranger a part sous le nom d'un
// module inutilise.
func unusedIDs(found []finding.Finding, unused map[string]map[string]bool) map[string]bool {
	if len(unused) == 0 {
		return nil
	}
	parent := map[string]string{}
	var root func(string) string
	root = func(id string) string {
		for parent[id] != id {
			parent[id] = parent[parent[id]]
			id = parent[id]
		}
		return id
	}
	for _, f := range found {
		ids := pkgIDs(f)
		for _, id := range ids {
			if _, ok := parent[id]; !ok {
				parent[id] = id
			}
		}
		for _, id := range ids[min(1, len(ids)):] {
			parent[root(id)] = root(ids[0])
		}
	}
	blocked := map[string]bool{}
	for _, f := range found {
		ids := pkgIDs(f)
		if len(ids) == 0 {
			continue
		}
		if manifest, mod := goDependency(f); mod == "" || !unused[manifest][mod] {
			blocked[root(ids[0])] = true
		}
	}
	out := map[string]bool{}
	for id := range parent {
		if !blocked[root(id)] {
			out[id] = true
		}
	}
	return out
}

// pkgIDs rend les identifiants publics d'un constat, chacun rattache a son
// paquet: une CVE qui touche x/net et stdlib fait deux noeuds, l'un peut etre
// inutilise sans l'autre.
func pkgIDs(f finding.Finding) []string {
	pkg := depIdentity(f)
	ids := publicIDs(f)
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = pkg + "|" + id
	}
	return out
}

// tagUnused etiquette, apres fusion, les dependances dont chaque identifiant
// est dans ids.
func tagUnused(kept []finding.Finding, ids map[string]bool) {
	if len(ids) == 0 {
		return
	}
	for i := range kept {
		f := &kept[i]
		if f.Target == nil || f.Target.Type != "dependency" {
			continue
		}
		pub := pkgIDs(*f)
		all := len(pub) > 0
		for _, id := range pub {
			all = all && ids[id]
		}
		if all {
			addContext(f, ContextUnused)
		}
	}
}

// goDependency rend le go.mod et le module d'un constat osv-scanner tire d'un
// go.mod du depot, ou deux chaines vides. Le go.mod n'est retenu que s'il est
// interroge (voir unusedIDs). stdlib n'est jamais un module a retirer.
func goDependency(f finding.Finding) (manifest, mod string) {
	if f.Target == nil || f.Target.Type != "dependency" {
		return "", ""
	}
	for _, e := range f.Evidence {
		if e.Type == "manifest" {
			if manifest != "" && manifest != e.Data {
				return "", ""
			}
			manifest = e.Data
		}
	}
	manifest = path.Clean(manifest)
	if path.Base(manifest) != "go.mod" || strings.HasPrefix(manifest, "../") || path.IsAbs(manifest) {
		return "", ""
	}
	mod = f.Target.Identifier
	if i := strings.LastIndexByte(mod, '@'); i > 0 {
		mod = mod[:i]
	}
	if mod == "stdlib" {
		return "", ""
	}
	return manifest, mod
}
