// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/terrypsv/Quaero/internal/audit"
	"github.com/terrypsv/Quaero/internal/github"
)

// runAudit evalue la sante des depots d'une requete et emet un rapport au schema
// partage. Sans -audit-json, il affiche un resume lisible. Code 1 si au moins un
// depot est en fail, 0 sinon, 2 en cas d'erreur.
func runAudit(phrase string, limit int, jsonPath string) (int, error) {
	client, err := github.New()
	if err != nil {
		return 2, err
	}

	rep, err := audit.Run(context.Background(), client, phrase, limit, version)
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
		fmt.Printf("[%-8s %-6s] %-30s %s\n",
			strings.ToUpper(string(f.Severity)), string(f.Status), f.ID, f.Title)
	}
	fmt.Printf("\n%d depot(s) evalue(s): %d fail, %d review\n", len(rep.Findings), fail, review)

	if jsonPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(jsonPath, append(data, '\n'), 0o644); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "rapport ecrit dans %s\n", jsonPath)
	}

	if fail > 0 {
		return 1, nil
	}
	return 0, nil
}
