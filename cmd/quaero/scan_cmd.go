// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/terrypsv/Quaero/internal/codescan"
)

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
func runScan(dir, jsonPath string) (int, error) {
	rep, err := codescan.Run(context.Background(), dir, version, selectScanners(dir)...)
	if err != nil {
		return 2, err
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
