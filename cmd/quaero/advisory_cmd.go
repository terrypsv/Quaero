// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
)

// runAdvisory lit un rapport ecrit par -scan-json. Sans identifiant, il liste
// les constats qui peuvent devenir un signalement. Avec -finding, il prepare le
// brouillon de ce constat, sur la sortie standard ou dans -advisory-out.
// Code 0 si tout s'est bien passe, 2 en cas d'erreur.
func runAdvisory(reportPath, id, outPath string) (int, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return 2, err
	}
	var rep finding.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return 2, fmt.Errorf("%s n'est pas un rapport de scan lisible: %w", reportPath, err)
	}

	if strings.TrimSpace(id) == "" {
		cands := advisory.Candidates(&rep)
		if len(cands) == 0 {
			fmt.Println("Aucun constat de code ou de dependance dans ce rapport.")
			return 0, nil
		}
		for _, f := range cands {
			fmt.Printf("[%-8s] %s\n           %s\n", strings.ToUpper(string(f.Severity)), f.ID, f.Title)
		}
		fmt.Printf("\n%d constat(s). Preparer un brouillon avec -finding <identifiant>.\n", len(cands))
		return 0, nil
	}

	f, err := advisory.Find(&rep, id)
	if err != nil {
		return 2, err
	}
	draft := advisory.Draft(&rep, f)
	if outPath == "" {
		fmt.Print(draft)
		return 0, nil
	}
	// 0600: un brouillon decrit une faille encore non corrigee. Il n'a pas a
	// etre lisible par les autres comptes de la machine.
	if err := os.WriteFile(outPath, []byte(draft), 0o600); err != nil {
		return 2, err
	}
	fmt.Fprintf(os.Stderr, "brouillon ecrit dans %s, a completer et verifier avant tout envoi\n", outPath)
	return 0, nil
}
