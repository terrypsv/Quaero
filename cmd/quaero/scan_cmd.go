// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/terrypsv/Quaero/internal/codescan"
	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/repo"
)

// resolveScanTarget transforme ce qui est passe a -scan en un dossier a
// analyser. Un dossier deja present sur le disque est analyse tel quel, en
// confiance. Sinon, une reference de depot GitHub est clonee dans un
// temporaire, analysee en mode non fiable, puis effacee.
//
// Un dossier local l'emporte sur une reference: "mon/projet" existant est lu
// sur le disque, pas clone depuis GitHub.
func resolveScanTarget(ctx context.Context, target string) (dir, label string, untrusted bool, cleanup func(), err error) {
	if info, statErr := os.Stat(target); statErr == nil && info.IsDir() {
		label = target
		if abs, absErr := filepath.Abs(target); absErr == nil {
			label = abs
		}
		return target, label, false, func() {}, nil
	}
	ref, ok := repo.Parse(target)
	if !ok {
		return "", "", false, func() {}, fmt.Errorf(
			"%q n'est ni un dossier local ni une reference de depot GitHub (owner/repo ou une URL github.com)", target)
	}
	fmt.Fprintf(os.Stderr, "clone de %s...\n", ref)
	token, _ := github.ResolveToken()
	dir, cleanup, err = cloneRepo(ctx, ref, token)
	if err != nil {
		return "", "", false, func() {}, err
	}
	return dir, "github.com/" + ref.String(), true, cleanup, nil
}

// selectScanners choisit les moteurs selon ce que contient le depot. Semgrep et
// osv-scanner couvrent la plupart des langages et se declenchent partout; les
// moteurs specifiques a Go ne s'ajoutent que si un go.mod est present, pour ne
// pas faire tourner un outil Go sur un projet qui ne l'est pas.
func selectScanners(dir string) []codescan.Scanner {
	scanners := []codescan.Scanner{
		codescan.Semgrep{},    // SAST multi-langages
		codescan.OSVScanner{}, // dependances vulnerables, tous ecosystemes
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		scanners = append(scanners,
			codescan.Govulncheck{}, // dependances Go, avec atteignabilite
			codescan.Gosec{},       // motifs non surs propres a Go
		)
	}
	return scanners
}

// runScan analyse le code d'un depot *local* et emet un rapport au schema
// partage. Sans -scan-json, il affiche un resume lisible. Code 1 si au moins un
// constat est en fail, 0 sinon, 2 en cas d'erreur.
//
// Rappel porte par l'outil lui-meme: les constats sortent en "review", jamais
// confirmes. Confirmer une faille et la divulguer de facon coordonnee reste un
// acte humain, hors de l'outil.
func runScan(target, jsonPath string, timeout time.Duration) (int, error) {
	// Ctrl+C arrete les moteurs puis laisse le nettoyage se faire: sans cela,
	// le processus s'arreterait net et le clone resterait dans le temporaire.
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()
	// Apres le premier Ctrl+C, le second quitte tout de suite.
	go func() {
		<-ctx.Done()
		stop()
	}()
	dir, label, untrusted, cleanup, err := resolveScanTarget(ctx, target)
	if err != nil {
		if ctx.Err() != nil {
			return 2, errInterrupted
		}
		return 2, err
	}
	defer cleanup()

	// Les moteurs tournent sans rien afficher, parfois plusieurs minutes: la
	// ligne part avant, pour qu'un terminal muet ne passe pas pour un blocage.
	fmt.Printf("Analyse de %s en cours, %s au plus par moteur. Ctrl+C pour arreter.\n", label, minutes(timeout))
	opt := codescan.Options{Timeout: timeout, Untrusted: untrusted}
	rep, err := codescan.RunWith(ctx, dir, version, opt, selectScanners(dir)...)
	if ctx.Err() != nil {
		// Un scan interrompu ne rend pas de rapport: des moteurs coupes en
		// route passeraient pour un depot verifie.
		return 2, errInterrupted
	}
	if err != nil {
		return 2, err
	}
	// Le rapport nomme la cible par son depot, pas par le dossier temporaire du
	// clone, qui ne dit rien a personne.
	rep.Run.Context["cible"] = label
	// Le commit analyse: un signalement doit dire quelle revision a ete lue,
	// le depot ayant pu changer entre le scan et l'envoi.
	if commit := headCommit(ctx, dir); commit != "" {
		rep.Run.Context["commit"] = commit
	}
	if untrusted {
		fmt.Println("Depot tiers: environnement des moteurs durci. Pour du code douteux, scanner dans une machine jetable.")
	}

	fail, review, offProduct := 0, 0, 0
	for _, f := range rep.Findings {
		switch f.Status {
		case "fail":
			fail++
		case "review":
			review++
		}
		// Les etiquettes de pre-tri suivent le titre: elles disent ou regarder
		// d'abord, sans rien retirer de la liste.
		tags := codescan.Contexts(f)
		suffix := ""
		if len(tags) > 0 {
			suffix = " (" + strings.Join(tags, ", ") + ")"
		}
		for _, t := range tags {
			if codescan.OffProduct(t) {
				offProduct++
				break
			}
		}
		fmt.Printf("[%-8s %-6s] %-40s %s%s\n",
			strings.ToUpper(string(f.Severity)), string(f.Status), f.ID, f.Title, suffix)
	}
	fmt.Printf("\n%d constat(s): %d fail, %d review", len(rep.Findings), fail, review)
	if merged, _ := rep.Run.Context["doublons_fusionnes"].(int); merged > 0 {
		fmt.Printf(", %d doublon(s) entre moteurs fusionne(s)", merged)
	}
	fmt.Println()
	if line := durationsLine(rep.Run.Context["durees_s"]); line != "" {
		fmt.Println(line)
	}
	if offProduct > 0 {
		fmt.Printf("Pre-tri: %d constat(s) dans des tests, des exemples, du code tiers ou genere, ou des dependances inutilisees.\n", offProduct)
	}
	// osv-scanner lit la version de Go du go.mod, govulncheck compile avec celle
	// de la machine: les deux ne disent pas la meme chose de stdlib.
	if v, _ := rep.Run.Context["go_compile"].(string); v != "" {
		fmt.Printf("govulncheck a compile avec %s, osv-scanner lit la version du go.mod.\n", v)
	}
	fmt.Println("Tous les constats sont a verifier manuellement avant toute declaration.")

	if jsonPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return 2, err
		}
		// 0600: le rapport porte des chemins locaux et, pour -scan, le detail des
		// failles du code analyse. Il n'a pas a etre lisible par les autres comptes.
		if err := os.WriteFile(jsonPath, append(data, '\n'), 0o600); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "rapport ecrit dans %s\n", jsonPath)
	}

	if fail > 0 {
		return 1, nil
	}
	return 0, nil
}

var errInterrupted = errors.New("scan interrompu, aucun rapport ecrit")

// stopSignals arretent Quaero proprement: Ctrl+C, arret demande, terminal
// ferme. Les moteurs vivent dans leur propre groupe de processus (proctree):
// sans ce nettoyage, ils survivraient a Quaero avec le clone ouvert.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// durationsLine resume le temps passe par chaque moteur, pour voir ou part la
// duree d'un scan. Vide si aucun moteur n'a tourne.
func durationsLine(v any) string {
	d, ok := v.(map[string]float64)
	if !ok || len(d) == 0 {
		return ""
	}
	names := make([]string, 0, len(d))
	for n := range d {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %.1fs", n, d[n]))
	}
	return "Durees: " + strings.Join(parts, ", ")
}

// minutes ecrit un delai pour un humain: « 15 min », « 90 s ». Zero ou moins
// vaut le delai par defaut des moteurs.
func minutes(d time.Duration) string {
	if d <= 0 {
		d = codescan.DefaultTimeout
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return fmt.Sprintf("%d s", int(d.Round(time.Second)/time.Second))
}
