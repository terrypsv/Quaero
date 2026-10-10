// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package codescan audite le code source d'un depot *local* et projette chaque
// constat dans le schema de constat partage, consommable par Acta.
//
// Deux principes gouvernent ce paquet.
//
// Il n'analyse qu'un chemin deja present sur le disque. Aucune enumeration de
// GitHub, aucun ciblage reseau: on clone un depot soi-meme, on pointe l'outil
// dessus. La selection de la cible reste un acte humain, hors de l'outil.
//
// Il n'invente aucun moteur. Il orchestre des analyseurs statiques etablis
// (govulncheck, gosec) et se contente de normaliser leurs sorties. Un scanner
// maison serait moins fiable sur ce qui est difficile, le tri des faux
// positifs, et donnerait l'illusion d'une autorite qu'il n'a pas.
//
// Tout constat sort en Status "review" et Declared=false. L'analyse statique
// produit des candidats, pas des verdicts: la confirmation et la divulgation
// coordonnee restent la main de l'operateur.
package codescan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Category est la categorie commune des constats de code emis par ce paquet.
const Category = "code-vulnerability"

// Scanner est un analyseur statique enfichable. *Govulncheck et *Gosec le
// satisfont; les tests injectent un double, sans binaire ni reseau.
type Scanner interface {
	// Name identifie l'analyseur dans le rapport.
	Name() string
	// Available dit si l'analyseur est installe et utilisable.
	Available() bool
	// Scan analyse le depot a dir et rend des constats normalises.
	Scan(ctx context.Context, dir string) ([]finding.Finding, error)
}

// Run lance chaque analyseur sur dir et agrege leurs constats dans un rapport
// unique au schema partage. Un analyseur absent n'est pas une erreur: il laisse
// un constat d'information et la course continue, parce qu'un rapport muet sur
// ce qu'il n'a pas pu mesurer serait trompeur.
func Run(ctx context.Context, dir, version string, scanners ...Scanner) (*finding.Report, error) {
	abs, err := absDir(dir)
	if err != nil {
		return nil, err
	}

	host, _ := os.Hostname()
	rep := finding.NewReport(
		finding.Tool{Name: "quaero", Version: version},
		host,
		map[string]any{
			"mode": "codescan",
			"path": abs,
		},
	)

	ran := []string{}
	for _, s := range scanners {
		if !s.Available() {
			rep.Add(unavailable(s.Name()))
			continue
		}
		ran = append(ran, s.Name())
		fs, err := s.Scan(ctx, abs)
		if err != nil {
			rep.Add(scanError(s.Name(), err))
			continue
		}
		for _, f := range fs {
			// Invariant de la couche: un scan n'emet jamais un constat deja
			// declare. La confirmation et la declaration sont des actes humains,
			// posterieurs et hors de l'outil.
			f.Declared = finding.Bool(false)
			rep.Add(f)
		}
	}
	rep.Run.Context["scanners"] = ran

	rep.Finish()
	return rep, nil
}

// absDir verifie que dir existe, est un dossier, et en rend le chemin absolu.
func absDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("chemin vide")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("chemin %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("chemin %q: n'est pas un dossier", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// unavailable est le constat laisse par un analyseur non installe.
func unavailable(name string) finding.Finding {
	return finding.Finding{
		ID:       "QRO-SCAN-ABSENT-" + name,
		Title:    "Analyseur non disponible: " + name,
		Category: Category,
		Severity: finding.SeverityInfo,
		Status:   finding.StatusReview,
		Observed: fmt.Sprintf("%s introuvable dans le PATH et dans %s", name, strings.Join(installDirs(), ", ")),
		Remediation: fmt.Sprintf(
			"Installer %s pour que cette couche d'analyse soit evaluee.", name),
		Declared: finding.Bool(false),
	}
}

// scanError est le constat laisse par un analyseur qui a echoue a l'execution.
func scanError(name string, err error) finding.Finding {
	return finding.Finding{
		ID:       "QRO-SCAN-ERREUR-" + name,
		Title:    "Echec de l'analyseur: " + name,
		Category: Category,
		Severity: finding.SeverityInfo,
		Status:   finding.StatusReview,
		Observed: err.Error(),
		Declared: finding.Bool(false),
	}
}
