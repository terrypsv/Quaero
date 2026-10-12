// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/repo"
)

// Le scan peut partir d'un depot public nomme a la main, pas seulement d'un
// chemin deja sur le disque. Nommer la cible reste un acte humain: Quaero ne
// cherche pas de cible, il clone celle qu'on lui donne, l'analyse, puis efface
// le clone. La lecture des references est dans internal/repo, partagee avec
// l'interface.

// cloneArgs construit les arguments d'un clone superficiel et prudent: une
// seule branche, aucune etiquette, pas de sous-modules (ils pointent ou ils
// veulent), et aucun hook installe ni lance.
func cloneArgs(url, dir string) []string {
	return []string{
		"-c", "core.hooksPath=",
		"-c", "protocol.file.allow=never",
		"clone", "--depth", "1", "--single-branch", "--no-tags", url, dir,
	}
}

// cloneRepo clone ref dans un dossier temporaire et rend ce dossier avec une
// fonction de nettoyage. L'appelant appelle toujours le nettoyage, meme en cas
// d'erreur de scan, pour ne pas laisser de code tiers sur le disque.
func cloneRepo(ctx context.Context, ref repo.Ref) (string, func(), error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", func() {}, fmt.Errorf("git introuvable, l'installer ou cloner a la main puis `-scan <chemin>`")
	}
	dir, err := os.MkdirTemp("", "quaero-scan-")
	if err != nil {
		return "", func() {}, err
	}
	// Un clone qui ne s'efface pas (fichier encore tenu par un sous-processus,
	// sous Windows) se dit dans le terminal, avec son chemin.
	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "attention: clone non efface, a supprimer a la main: %s (%v)\n", dir, err)
		}
	}

	// #nosec G204 -- git est resolu par LookPath, l'URL est construite a partir
	// d'un owner/repo valide, le dossier est un temporaire a nous.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, git, cloneArgs(ref.CloneURL(), dir)...)
	// Un clone annule depuis l'interface tue git, mais son assistant HTTPS peut
	// garder la sortie ouverte: on ne l'attend pas indefiniment.
	cmd.WaitDelay = 5 * time.Second
	// Pas d'invite d'authentification: un depot absent ou prive echoue vite au
	// lieu de bloquer en attendant un mot de passe.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("clone de %s impossible: %s", ref, firstLine(out))
	}
	return dir, cleanup, nil
}

// headCommit rend le commit courant du depot a dir, ou "" si ce n'est pas un
// depot git ou si git est absent. C'est une information de contexte: son
// absence n'empeche pas le scan.
func headCommit(ctx context.Context, dir string) string {
	git, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	// #nosec G204 -- git resolu par LookPath, arguments fixes, dossier analyse.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	out, err := exec.CommandContext(ctx, git, "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	commit := strings.TrimSpace(string(out))
	if !commitRe.MatchString(commit) {
		return ""
	}
	return commit
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// firstLine garde la premiere ligne utile d'une sortie d'erreur de git, pour un
// message court plutot qu'un pave.
func firstLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return "erreur inconnue"
}
