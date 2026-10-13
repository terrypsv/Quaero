// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Une relance de Quaero reprend l'onglet deja ouvert au lieu d'en ouvrir un
// autre. Deux pieces y suffisent.
//
// Le jeton de session est garde entre deux lancements, dans le dossier de
// l'utilisateur et lisible par lui seul, comme le jeton GitHub. L'onglet
// ouvert avant la relance le connait deja, il reste valable.
//
// La page tient une requete ouverte sur /api/presence. Quand Quaero s'arrete,
// elle tombe et la page le dit. Elle retente chaque seconde, et la premiere
// requete qui passe apres la relance prouve a Quaero qu'un onglet l'attend:
// il n'ouvre pas le navigateur.

// sessionFile est le nom du fichier du jeton, a cote de la configuration.
const sessionFile = "session"

// presenceHold borne la duree d'une requete de presence. La page en relance
// une aussitot, la limite ne sert qu'a ne rien laisser pendre indefiniment.
var presenceHold = 25 * time.Second

// tokenRe est la forme d'un jeton tire par NewToken.
var tokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SessionPath rend ~/.quaero/session.
func SessionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("repertoire personnel introuvable: %w", err)
	}
	return filepath.Join(home, ".quaero", sessionFile), nil
}

// SessionToken relit le jeton garde dans path, ou en tire un neuf et l'y
// ecrit. reused dit qu'un onglet ouvert avant la relance peut le reprendre. Un
// fichier lisible par d'autres que l'utilisateur n'est pas repris: le jeton
// est retire. En cas d'erreur d'ecriture, le jeton rendu reste utilisable le
// temps de cette execution.
func SessionToken(path string) (token string, reused bool, err error) {
	if t, ok := readToken(path); ok {
		return t, true, nil
	}
	token, err = NewToken()
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return token, false, err
	}
	// Un fichier existant garde ses droits a l'ecriture: il est remplace.
	_ = os.Remove(path)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return token, false, err
	}
	return token, false, nil
}

func readToken(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", false
	}
	// #nosec G304 -- chemin fixe sous le dossier utilisateur (SessionPath),
	// jamais issu d'une requete.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	t := strings.TrimSpace(string(data))
	return t, tokenRe.MatchString(t)
}

// notePresence retient qu'une page de la session vient de parler a Quaero.
func (s *Server) notePresence() {
	select {
	case s.presence <- struct{}{}:
	default:
	}
}

// WaitPresence attend au plus d qu'un onglet deja ouvert se manifeste. A
// appeler apres Handler, une fois le serveur a l'ecoute.
func (s *Server) WaitPresence(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.presence:
		return true
	case <-t.C:
		return false
	}
}

// handlePresence tient la requete ouverte jusqu'a l'arret de Quaero, la
// fermeture de l'onglet ou presenceHold. Elle ne rend rien d'autre.
func (s *Server) handlePresence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	t := time.NewTimer(presenceHold)
	defer t.Stop()
	select {
	case <-r.Context().Done():
	case <-t.C:
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
