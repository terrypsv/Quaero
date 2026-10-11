// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// waitDelay borne l'attente des sorties d'un moteur deja interrompu. Sans elle,
// un sous-processus qui garde sa sortie ouverte peut bloquer le scan bien apres
// l'expiration du delai.
const waitDelay = 5 * time.Second

// toolResult est ce qu'un moteur a rendu: sa sortie standard, un extrait de sa
// sortie d'erreur et son code de sortie.
type toolResult struct {
	name     string
	stdout   []byte
	stderr   string
	exitCode int
}

// runTool lance un moteur sans shell et rend ce qu'il a produit. Il ne juge pas
// le code de sortie: chaque moteur a le sien, et plusieurs sortent en non nul
// pour dire qu'ils ont trouve quelque chose. Il n'echoue que si le processus n'a
// pas pu demarrer ou s'il a ete interrompu.
func runTool(ctx context.Context, bin, dir string, args ...string) (toolResult, error) {
	// #nosec G204 -- aucun shell: binaire resolu depuis un nom fixe, arguments
	// separes, et le chemin analyse est absolu (absDir), jamais lu comme une option.
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.WaitDelay = waitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := toolResult{
		name:   filepath.Base(bin),
		stdout: stdout.Bytes(),
		stderr: excerpt(stderr.String()),
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exitCode = exitErr.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// accept dit si le code de sortie fait partie de ceux qui signifient "analyse
// terminee" pour ce moteur. Un code non nul sans aucune sortie reste une panne:
// sinon un moteur en echec passerait pour un moteur qui n'a rien trouve.
func (r toolResult) accept(codes ...int) error {
	for _, c := range codes {
		if r.exitCode != c {
			continue
		}
		if r.exitCode == 0 || len(bytes.TrimSpace(r.stdout)) > 0 {
			return nil
		}
		break
	}
	return r.failure()
}

// failure decrit une panne du moteur avec ce qu'il a dit sur sa sortie d'erreur.
func (r toolResult) failure() error {
	if r.stderr != "" {
		return fmt.Errorf("%s: code de sortie %d (%s)", r.name, r.exitCode, r.stderr)
	}
	return fmt.Errorf("%s: code de sortie %d, sans sortie exploitable", r.name, r.exitCode)
}

// excerpt garde le debut de la sortie d'erreur: assez pour diagnostiquer, pas
// assez pour noyer le rapport.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	const limit = 400
	if len(s) > limit {
		return strings.ToValidUTF8(s[:limit], "") + "..."
	}
	return s
}
