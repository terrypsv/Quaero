// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/proctree"
	"github.com/terrypsv/Quaero/internal/repo"
)

// Le scan peut partir d'un depot nomme a la main, pas seulement d'un chemin
// deja sur le disque. Nommer la cible reste un acte humain: Quaero ne cherche
// pas de cible, il clone celle qu'on lui donne, l'analyse, puis efface le
// clone. La lecture des references est dans internal/repo, partagee avec
// l'interface.
//
// Le clone se fait d'abord sans aucun identifiant. Seul un depot que GitHub
// refuse en anonyme (prive, ou absent) est retente avec le jeton de
// l'utilisateur: un depot public ne voit jamais passer le jeton.

// cloneArgs construit les arguments d'un clone superficiel et prudent: une
// seule branche, aucune etiquette, pas de sous-modules (ils pointent ou ils
// veulent), aucun hook installe ni lance. Aucun identifiant de l'utilisateur
// n'est sollicite: ni gestionnaire d'identifiants, ni programme askpass, ni
// cle SSH. Le transport est HTTPS et rien d'autre, et l'adresse est figee sur
// elle-meme pour qu'une reecriture de l'utilisateur (url.<x>.insteadOf vers
// git@github.com:) ne la detourne pas vers SSH.
func cloneArgs(url, dir string) []string {
	return []string{
		"-c", "core.hooksPath=",
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.file.allow=never",
		"-c", "url." + url + ".insteadOf=" + url,
		"-c", "credential.helper=",
		"-c", "core.askPass=",
		"clone", "--depth", "1", "--single-branch", "--no-tags", url, dir,
	}
}

// cloneEnv rend l'environnement de git. Avec un jeton, il le passe dans un
// en-tete reserve a github.com, par l'environnement et non par la ligne de
// commande, qui se lit dans la liste des processus.
func cloneEnv(token string) []string {
	env := append(os.Environ(),
		// Pas d'invite: un depot absent ou prive echoue vite au lieu
		// d'attendre un mot de passe, en console comme en fenetre.
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
		// Vide, il l'emporte sur SSH_ASKPASS et core.askPass: aucun
		// programme ne fournit d'identifiant a la place de l'utilisateur.
		"GIT_ASKPASS=",
		// Les gros fichiers LFS ne servent pas a l'analyse.
		"GIT_LFS_SKIP_SMUDGE=1",
	)
	if token != "" {
		// Les reglages git deja passes par l'environnement (proxy, reecriture
		// d'adresses) sont gardes: l'en-tete s'ajoute a leur suite.
		n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("GIT_CONFIG_COUNT")))
		if n < 0 {
			n = 0
		}
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_COUNT=%d", n+1),
			fmt.Sprintf("GIT_CONFIG_KEY_%d=http.https://github.com/.extraheader", n),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=AUTHORIZATION: basic %s", n, basic),
		)
	}
	return env
}

// needsAuth dit si git a echoue faute d'identifiants: GitHub repond ainsi en
// anonyme pour un depot prive comme pour un depot qui n'existe pas.
func needsAuth(out string) bool {
	for _, s := range []string{"could not read Username", "terminal prompts disabled", "Authentication failed", "Invalid username or password"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}

// cloneRepo clone ref dans un dossier temporaire et rend ce dossier avec une
// fonction de nettoyage. L'appelant appelle toujours le nettoyage, meme en cas
// d'erreur de scan, pour ne pas laisser de code tiers sur le disque. token
// peut etre vide; il ne sert que si GitHub refuse le clone anonyme.
func cloneRepo(ctx context.Context, ref repo.Ref, token string) (string, func(), error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", func() {}, fmt.Errorf("git introuvable, l'installer ou cloner a la main puis `-scan <chemin>`")
	}
	return cloneWith(ctx, git, ref, token)
}

// cloneWith fait le travail de cloneRepo avec le git donne.
func cloneWith(ctx context.Context, git string, ref repo.Ref, token string) (string, func(), error) {
	dir, err := os.MkdirTemp("", cloneDirPrefix)
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { removeClone(dir) }

	out, err := runClone(ctx, git, ref, dir, "")
	withToken := false
	if err != nil && needsAuth(out) && token != "" && ctx.Err() == nil {
		// Un clone rate peut laisser un .git partiel: on repart d'un dossier
		// vide pour la seconde tentative.
		if err = resetDir(dir); err == nil {
			withToken = true
			out, err = runClone(ctx, git, ref, dir, token)
		}
	}
	if err != nil {
		cleanup()
		return "", func() {}, cloneError(ref, out, err, withToken)
	}
	return dir, cleanup, nil
}

// resetDir vide dir en le recreant.
func resetDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.Mkdir(dir, 0o700)
}

// cloneError dit pourquoi un clone a echoue, en termes d'action: un depot
// prive se lit avec un jeton qui y a acces, ou se clone a la main.
func cloneError(ref repo.Ref, out string, err error, withToken bool) error {
	switch {
	case withToken && needsAuth(out):
		return fmt.Errorf("jeton refuse par GitHub pour cloner %s: expire, revoque, ou sans acces a ce depot", ref)
	case withToken && strings.Contains(out, "not found"):
		return fmt.Errorf("%s introuvable, ou prive et hors de portee du jeton (il doit pouvoir lire le contenu du depot)", ref)
	case needsAuth(out):
		return fmt.Errorf("%s introuvable, ou prive. Pour un depot prive, enregistrer un jeton qui peut le lire (quaero -save-token), ou le cloner soi-meme puis analyser le dossier", ref)
	case out == "":
		return fmt.Errorf("clone de %s impossible: %v", ref, err)
	}
	return fmt.Errorf("clone de %s impossible: %s", ref, gitFailure(out))
}

// gitFailure garde de la sortie de git la ligne qui dit l'erreur: la premiere
// ligne "fatal:", sinon la derniere ligne non vide ("Cloning into" ne dit rien).
func gitFailure(out string) string {
	last := ""
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "fatal:") {
			return l
		}
		if l != "" {
			last = l
		}
	}
	if last == "" {
		return "erreur inconnue"
	}
	return last
}

// runClone lance un clone et rend sa sortie. Annule, git est arrete avec son
// assistant HTTPS (voir proctree).
func runClone(ctx context.Context, git string, ref repo.Ref, dir, token string) (string, error) {
	// #nosec G204 -- git est resolu par LookPath, l'URL est construite a partir
	// d'un owner/repo valide, le dossier est un temporaire a nous.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, git, cloneArgs(ref.CloneURL(), dir)...)
	proctree.Prepare(cmd)
	cmd.Env = cloneEnv(token)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// cloneDirPrefix nomme les clones temporaires, pour les reconnaitre s'il en
// reste.
const cloneDirPrefix = "quaero-scan-"

// removeClone efface un clone. Sous Windows, un fichier peut rester tenu un
// instant apres l'arret des processus qui le lisaient: on reessaie avant de
// renoncer, et un clone qui reste se dit dans le terminal, avec son chemin.
func removeClone(dir string) {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "attention: clone non efface, a supprimer a la main: %s (%v)\n", dir, err)
}

// staleClones liste les clones laisses par une execution precedente, plus
// vieux que age. Quaero ne les efface pas lui-meme: un autre Quaero pourrait
// etre en train d'en lire un.
func staleClones(tmp string, age time.Duration) []string {
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), cloneDirPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < age {
			continue
		}
		out = append(out, filepath.Join(tmp, e.Name()))
	}
	return out
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
