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

	"github.com/terrypsv/Quaero/internal/proctree"
)

// toolResult est ce qu'un moteur a rendu: sa sortie standard, un extrait de sa
// sortie d'erreur et son code de sortie.
type toolResult struct {
	name   string
	stdout []byte
	stderr string
	// stderrTail est la fin de la sortie d'erreur: un message final peut
	// suivre des lignes de telechargement que l'extrait de tete coupe.
	stderrTail string
	exitCode   int
	// root est le dossier analyse: les chemins rendus par le moteur sont
	// ramenes sous lui (voir relTo).
	root string
}

// runTool lance un moteur sans shell et rend ce qu'il a produit. Il ne juge pas
// le code de sortie: chaque moteur a le sien, et plusieurs sortent en non nul
// pour dire qu'ils ont trouve quelque chose. Il n'echoue que si le processus n'a
// pas pu demarrer ou s'il a ete interrompu.
func runTool(ctx context.Context, bin, dir string, args ...string) (toolResult, error) {
	// Aucun shell: binaire resolu depuis un nom fixe, arguments separes, et le
	// chemin analyse est absolu (absDir), jamais lu comme une option. gosec et
	// semgrep signalent quand meme cet appel, d'ou les deux annotations.
	// #nosec G204 -- justification ci-dessus
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// Interrompu, le moteur est arrete avec tout ce qu'il a lance, et l'attente
	// de ses sorties reste bornee (voir proctree).
	proctree.Prepare(cmd)
	// Un scan marque non fiable impose un environnement durci aux moteurs
	// (voir sandbox.go). Les variables s'ajoutent apres celles du processus,
	// donc elles l'emportent.
	if env := scanEnv(ctx); env != nil {
		cmd.Env = append(cmd.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := toolResult{
		name:       filepath.Base(bin),
		stdout:     stdout.Bytes(),
		stderr:     excerpt(stderr.String()),
		stderrTail: tail(stderr.String()),
		root:       dir,
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

// tail garde la fin de la sortie d'erreur, dans la meme limite qu'excerpt.
func tail(s string) string {
	s = strings.TrimSpace(s)
	const limit = 400
	if len(s) > limit {
		return strings.ToValidUTF8(s[len(s)-limit:], "")
	}
	return s
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
