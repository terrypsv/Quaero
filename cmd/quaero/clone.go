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
)

// Le scan peut partir d'un depot public nomme a la main, pas seulement d'un
// chemin deja sur le disque. Nommer la cible reste un acte humain: Quaero ne
// cherche pas de cible, il clone celle qu'on lui donne, l'analyse, puis efface
// le clone.
//
// Seul github.com est accepte, en lecture publique par HTTPS. Un autre hote ou
// un depot prive se clone a la main, puis s'analyse avec `-scan <chemin>`.

// repoRef est une reference de depot GitHub reduite a owner/repo.
type repoRef struct {
	Owner string
	Repo  string
}

func (r repoRef) String() string   { return r.Owner + "/" + r.Repo }
func (r repoRef) cloneURL() string { return "https://github.com/" + r.Owner + "/" + r.Repo + ".git" }

var (
	// Login GitHub: lettres, chiffres et tirets simples, 39 au plus.
	ownerPat = `[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?`
	// Nom de depot GitHub: lettres, chiffres, point, tiret, souligne.
	repoPat = `[A-Za-z0-9._-]{1,100}`
	refRe   = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/(` + ownerPat + `)/(` + repoPat + `)$`)
	bareRe  = regexp.MustCompile(`^(` + ownerPat + `)/(` + repoPat + `)$`)
	sshRe   = regexp.MustCompile(`^git@github\.com:(` + ownerPat + `)/(` + repoPat + `)$`)
)

// parseRepoRef lit une reference de depot GitHub sous ses formes usuelles
// (owner/repo, URL https, URL git@), ou dit qu'elle n'en est pas une.
func parseRepoRef(s string) (repoRef, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	for _, re := range []*regexp.Regexp{refRe, sshRe, bareRe} {
		if m := re.FindStringSubmatch(s); m != nil {
			repo := m[2]
			// "." et ".." ne sont pas des depots, et un nom tout en points
			// n'ouvre pas de chemin.
			if repo == "." || repo == ".." || strings.Trim(repo, ".") == "" {
				return repoRef{}, false
			}
			return repoRef{Owner: m[1], Repo: repo}, true
		}
	}
	return repoRef{}, false
}

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
func cloneRepo(ctx context.Context, ref repoRef) (string, func(), error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", func() {}, fmt.Errorf("git introuvable, l'installer ou cloner a la main puis `-scan <chemin>`")
	}
	dir, err := os.MkdirTemp("", "quaero-scan-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	// #nosec G204 -- git est resolu par LookPath, l'URL est construite a partir
	// d'un owner/repo valide, le dossier est un temporaire a nous.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, git, cloneArgs(ref.cloneURL(), dir)...)
	// Pas d'invite d'authentification: un depot absent ou prive echoue vite au
	// lieu de bloquer en attendant un mot de passe.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("clone de %s impossible: %s", ref, firstLine(out))
	}
	return dir, cleanup, nil
}

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
