// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Un depot peut porter plusieurs modules Go: un go.mod a la racine, un autre
// pour une console ou un installeur dans un sous-dossier. « ./... » s'arrete a
// la frontiere d'un module, govulncheck et gosec lances a la racine ne voient
// donc pas les autres. Quaero les trouve et les analyse chacun, la racine
// d'abord. osv-scanner, lui, lit deja tous les go.mod.

// MaxGoModules borne le nombre de modules analyses dans un depot. Au-dela, le
// rapport dit ce qui n'a pas ete vu.
const MaxGoModules = 20

// maxWalkEntries borne la recherche des go.mod: un clone hostile ou geant ne
// doit pas la faire durer. Au-dela, le rapport dit qu'elle s'est arretee.
var maxWalkEntries = 200000

// skipDirs sont les dossiers ou un go.mod n'est pas un module du depot: code
// recopie d'un tiers, jeux d'essai, dependances JavaScript.
var skipDirs = set("vendor", "node_modules", "testdata")

// GoModules rend les dossiers des modules Go du depot, relatifs a dir et en
// barres obliques. La racine (".") vient d'abord, puis les modules du produit,
// les moins profonds d'abord, puis ceux d'exemple, de test ou de code tiers
// (voir offProductModule). Comme pour « ./... », les dossiers dont le nom
// commence par un point ou un tiret bas sont ignores, et un lien symbolique
// n'est jamais suivi. Un go.work n'y change rien: chaque module s'analyse avec
// son propre go.mod (voir goWorkOff). more dit que la recherche s'est arretee
// avant la fin.
func GoModules(dir string) (mods []string, more bool) {
	seen := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if seen++; seen > maxWalkEntries {
			more = true
			return filepath.SkipAll
		}
		if err != nil {
			if d != nil && d.IsDir() && p != dir {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if p != dir && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || skipDirs[name]) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" && d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, filepath.Dir(p))
			if err == nil {
				mods = append(mods, path.Clean(filepath.ToSlash(rel)))
			}
		}
		return nil
	})
	rank := func(m string) (int, int) {
		switch {
		case m == ".":
			return 0, 0
		case offProductModule(m):
			return 2, strings.Count(m, "/")
		}
		return 1, strings.Count(m, "/")
	}
	sort.SliceStable(mods, func(i, j int) bool {
		gi, di := rank(mods[i])
		gj, dj := rank(mods[j])
		if gi != gj {
			return gi < gj
		}
		if di != dj {
			return di < dj
		}
		return mods[i] < mods[j]
	})
	return mods, more
}

// offProductModule dit si un module vit dans un dossier d'exemple, de test ou
// de code tiers, selon les memes regles que le pre-tri des chemins.
func offProductModule(rel string) bool {
	for _, tag := range pathTags(path.Join(rel, "go.mod")) {
		if OffProduct(tag) {
			return true
		}
	}
	return false
}

// goWorkOff analyse chaque module avec son propre go.mod. Un go.work changerait
// les versions (un seul jeu pour tout l'espace de travail), refuserait le
// -mod=mod du mode non fiable, et ferait echouer un module qu'il ne liste pas.
func goWorkOff(ctx context.Context) context.Context {
	return withExtraEnv(ctx, "GOWORK=off")
}

// regular dit si p est un fichier ordinaire, sans suivre de lien.
func regular(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode().IsRegular()
}

// moduleDir rend le chemin absolu du module rel dans dir.
func moduleDir(dir, rel string) string {
	return filepath.Join(dir, filepath.FromSlash(rel))
}

// moduleLabel nomme un module dans le rapport: « module cmd/console », rien
// pour la racine.
func moduleLabel(rel string) string {
	if rel == "." || rel == "" {
		return ""
	}
	return "module " + rel
}

// manifestOf rend le go.mod d'un module, relatif au depot.
func manifestOf(rel string) string {
	return path.Join(rel, "go.mod")
}
