// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/codescan"
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
		return target, target, false, func() {}, nil
	}
	ref, ok := parseRepoRef(target)
	if !ok {
		return "", "", false, func() {}, fmt.Errorf(
			"%q n'est ni un dossier local ni une reference de depot GitHub (owner/repo ou une URL github.com)", target)
	}
	fmt.Fprintf(os.Stderr, "clone de %s...\n", ref)
	dir, cleanup, err = cloneRepo(ctx, ref)
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
	ctx := context.Background()
	dir, label, untrusted, cleanup, err := resolveScanTarget(ctx, target)
	if err != nil {
		return 2, err
	}
	defer cleanup()

	opt := codescan.Options{Timeout: timeout, Untrusted: untrusted}
	rep, err := codescan.RunWith(ctx, dir, version, opt, selectScanners(dir)...)
	if err != nil {
		return 2, err
	}
	// Le rapport nomme la cible par son depot, pas par le dossier temporaire du
	// clone, qui ne dit rien a personne.
	rep.Run.Context["cible"] = label
	fmt.Printf("Analyse de %s\n", label)
	if untrusted {
		fmt.Println("Depot tiers: environnement des moteurs durci. Pour du code douteux, scanner dans une machine jetable.")
	}

	fail, review := 0, 0
	for _, f := range rep.Findings {
		switch f.Status {
		case "fail":
			fail++
		case "review":
			review++
		}
		fmt.Printf("[%-8s %-6s] %-40s %s\n",
			strings.ToUpper(string(f.Severity)), string(f.Status), f.ID, f.Title)
	}
	fmt.Printf("\n%d constat(s): %d fail, %d review", len(rep.Findings), fail, review)
	if merged, _ := rep.Run.Context["doublons_fusionnes"].(int); merged > 0 {
		fmt.Printf(", %d doublon(s) entre moteurs fusionne(s)", merged)
	}
	fmt.Println()
	if line := durationsLine(rep.Run.Context["durees_s"]); line != "" {
		fmt.Println(line)
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
