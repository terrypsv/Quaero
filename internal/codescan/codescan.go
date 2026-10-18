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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

// buildScanner est un moteur qui apprend aussi du depot Go: la version de Go
// qui compile, les modules de chaque go.mod que rien n'importe. *Govulncheck le
// satisfait.
type buildScanner interface {
	Scanner
	ScanBuild(ctx context.Context, dir string) ([]finding.Finding, *goFacts, error)
}

// deadlineScanner est un moteur qui gere lui-meme son delai: ce qu'il rend sans
// erreur apres l'echeance est un resultat partiel qu'il a signale, pas un
// resultat tronque. *Govulncheck et *Gosec le satisfont, eux qui enchainent
// plusieurs modules.
type deadlineScanner interface {
	Scanner
	handlesDeadline()
}

// DefaultTimeout borne la duree accordee a chaque moteur. Un moteur bloque ne
// doit pas bloquer le scan entier: au-dela, il est interrompu et le rapport le
// dit, plutot que de rendre la main sans fin.
const DefaultTimeout = 15 * time.Minute

// Options regle une execution de Run.
type Options struct {
	// Timeout borne chaque moteur. Zero ou negatif vaut DefaultTimeout.
	Timeout time.Duration
	// Untrusted durcit l'environnement des moteurs pour un depot dont on n'a
	// pas la maitrise (un clone tiers): pas de changement de chaine d'outils,
	// pas de cgo, pas d'invite. Voir sandbox.go. Un scan local reste normal.
	Untrusted bool
}

// Run lance les analyseurs avec les options par defaut. Voir RunWith.
func Run(ctx context.Context, dir, version string, scanners ...Scanner) (*finding.Report, error) {
	return RunWith(ctx, dir, version, Options{}, scanners...)
}

// outcome est ce qu'un moteur a rendu, garde a sa place pour que le rapport
// reste dans l'ordre des moteurs quel que soit celui qui finit le premier.
type outcome struct {
	available bool
	findings  []finding.Finding
	facts     *goFacts
	err       error
	elapsed   time.Duration
}

// RunWith lance chaque analyseur sur dir et agrege leurs constats dans un
// rapport unique au schema partage.
//
// Les moteurs tournent en parallele: ils ne partagent rien et le plus lent
// fixait jusqu'ici la duree du total des autres. Chacun a son propre delai. Un
// moteur absent, en panne ou interrompu laisse un constat d'information plutot
// que de disparaitre, parce qu'un rapport muet sur ce qu'il n'a pas pu mesurer
// serait trompeur.
func RunWith(ctx context.Context, dir, version string, opt Options, scanners ...Scanner) (*finding.Report, error) {
	abs, err := absDir(dir)
	if err != nil {
		return nil, err
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	if opt.Untrusted {
		ctx = withScanEnv(ctx, hardenedEnv())
	}

	host, _ := os.Hostname()
	rep := finding.NewReport(
		finding.Tool{Name: "quaero", Version: version},
		host,
		map[string]any{
			"mode":       "codescan",
			"path":       abs,
			"non_fiable": opt.Untrusted,
		},
	)

	results := make([]outcome, len(scanners))
	var wg sync.WaitGroup
	for i, s := range scanners {
		if !s.Available() {
			continue
		}
		results[i].available = true
		wg.Add(1)
		go func(i int, s Scanner) {
			defer wg.Done()
			results[i] = runOne(ctx, s, abs, timeout)
		}(i, s)
	}
	wg.Wait()

	ran := []string{}
	durations := map[string]float64{}
	var found []finding.Finding
	var facts *goFacts
	for i, s := range scanners {
		r := results[i]
		if !r.available {
			rep.Add(unavailable(s.Name()))
			continue
		}
		ran = append(ran, s.Name())
		durations[s.Name()] = math.Round(r.elapsed.Seconds()*100) / 100
		if r.err != nil {
			rep.Add(scanError(s.Name(), r.err))
			continue
		}
		if facts == nil {
			facts = r.facts
		}
		for _, f := range r.findings {
			// Invariant de la couche: un scan n'emet jamais un constat deja
			// declare. La confirmation et la declaration sont des actes humains,
			// posterieurs et hors de l'outil.
			f.Declared = finding.Bool(false)
			// La provenance est gardee: c'est elle qui permet de fusionner deux
			// moteurs d'accord sans perdre qu'ils l'etaient.
			f.Evidence = append(f.Evidence, finding.Evidence{Type: EvidenceEngine, Data: s.Name()})
			found = append(found, f)
		}
	}

	// Les dependances inutilisees se reconnaissent avant la fusion, tant que
	// chaque constat garde son manifeste et son module.
	var unused map[string]bool
	if facts != nil {
		unused = unusedIDs(found, facts.unused)
	}
	kept := pretri(abs, uniqueIDs(mergeSameLine(dedupe(found))))
	tagUnused(kept, unused)
	for _, f := range kept {
		rep.Add(f)
	}
	rep.Run.Context["scanners"] = ran
	// Une fusion silencieuse serait un mensonge par omission: le rapport dit
	// combien de constats en double ont ete regroupes.
	rep.Run.Context["doublons_fusionnes"] = len(found) - len(kept)
	// La duree de chaque moteur dit ou passe le temps d'un scan.
	rep.Run.Context["durees_s"] = durations
	rep.Run.Context["delai_moteur_s"] = timeout.Seconds()
	// La version de Go qui a compile le depot pour govulncheck. osv-scanner, lui,
	// lit celle du go.mod, souvent plus ancienne.
	if facts != nil && facts.goVersion != "" {
		rep.Run.Context["go_compile"] = facts.goVersion
	}

	rep.Finish()
	return rep, nil
}

// runOne execute un moteur sous son propre delai. Un moteur interrompu est une
// panne, meme s'il a rendu une liste vide sans erreur: un resultat partiel ne
// doit jamais passer pour un depot sain.
func runOne(ctx context.Context, s Scanner, dir string, timeout time.Duration) outcome {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var (
		fs       []finding.Finding
		facts    *goFacts
		err      error
		selfTime bool
	)
	if b, ok := s.(buildScanner); ok {
		fs, facts, err = b.ScanBuild(sctx, dir)
	} else {
		fs, err = s.Scan(sctx, dir)
	}
	_, self := s.(deadlineScanner)
	selfTime = self && err == nil
	out := outcome{available: true, findings: fs, facts: facts, err: err, elapsed: time.Since(start)}

	switch ctxErr := sctx.Err(); {
	case errors.Is(ctxErr, context.DeadlineExceeded) && selfTime:
		// Le moteur a garde ce qui etait fini et dit ce qui manque.
	case errors.Is(ctxErr, context.DeadlineExceeded):
		out.findings, out.facts = nil, nil
		out.err = fmt.Errorf("interrompu apres %s, delai maximal atteint", timeout)
	case ctxErr != nil:
		out.findings, out.facts = nil, nil
		out.err = fmt.Errorf("interrompu: %w", ctxErr)
	}
	return out
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

// nothingToCheck est le constat laisse par un moteur qui a tourne sans rien
// trouver a analyser. Ce n'est pas un depot sain: c'est un depot non verifie.
func nothingToCheck(name, observed, remediation string) finding.Finding {
	return finding.Finding{
		ID:          "QRO-SCAN-VIDE-" + name,
		Title:       "Rien a analyser pour " + name,
		Category:    Category,
		Severity:    finding.SeverityInfo,
		Status:      finding.StatusReview,
		Observed:    observed,
		Remediation: remediation,
		Declared:    finding.Bool(false),
	}
}

// partialScan est le constat laisse par un moteur qui n'a pas pu tout analyser:
// govulncheck en echec pour un systeme, mais pas pour les autres. Ce qui a ete
// analyse reste dans le rapport, et le rapport dit ce qui manque.
func partialScan(name string, failed []string) finding.Finding {
	return finding.Finding{
		ID:          "QRO-SCAN-PARTIEL-" + name,
		Title:       "Analyse partielle: " + name,
		Category:    Category,
		Severity:    finding.SeverityInfo,
		Status:      finding.StatusReview,
		Observed:    strings.Join(failed, " ; "),
		Remediation: "Souvent un depot qui ne vise pas ce systeme. Sinon, la raison dit ce qui a bloque.",
		Declared:    finding.Bool(false),
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
