// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestEnvHelperProcess n'est pas un test: c'est un faux moteur qui imprime la
// valeur d'une variable d'environnement, pour verifier que runTool l'impose.
func TestEnvHelperProcess(t *testing.T) {
	if os.Getenv("QUAERO_ENV_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	key := ""
	if len(args) > 1 {
		key = args[1]
	}
	os.Stdout.WriteString(os.Getenv(key))
	os.Exit(0)
}

func runEnvHelper(t *testing.T, ctx context.Context, key string) string {
	t.Helper()
	t.Setenv("QUAERO_ENV_HELPER", "1")
	args := []string{"-test.run=^TestEnvHelperProcess$", "--", key}
	res, err := runTool(ctx, os.Args[0], t.TempDir(), args...)
	if err != nil {
		t.Fatalf("runTool: %v", err)
	}
	return string(res.stdout)
}

// Le mode non fiable impose son environnement aux moteurs.
func TestEnvDurciImpose(t *testing.T) {
	ctx := withScanEnv(context.Background(), hardenedEnv())
	if got := runEnvHelper(t, ctx, "GOTOOLCHAIN"); got != "local" {
		t.Errorf("GOTOOLCHAIN = %q, attendu local", got)
	}
	if got := runEnvHelper(t, ctx, "CGO_ENABLED"); got != "0" {
		t.Errorf("CGO_ENABLED = %q, attendu 0", got)
	}
}

// Sans durcissement, l'environnement du processus passe tel quel.
func TestEnvNormalInchange(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	if got := runEnvHelper(t, context.Background(), "CGO_ENABLED"); got != "1" {
		t.Errorf("CGO_ENABLED = %q, attendu 1 (inchange)", got)
	}
}

// hardenedEnv ferme bien les chemins d'execution connus.
func TestHardenedEnvContenu(t *testing.T) {
	env := strings.Join(hardenedEnv(), " ")
	for _, want := range []string{"GOTOOLCHAIN=local", "CGO_ENABLED=0", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(env, want) {
			t.Errorf("environnement durci sans %q: %s", want, env)
		}
	}
}
