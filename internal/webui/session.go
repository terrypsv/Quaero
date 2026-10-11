// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

// La session protege l'interface locale.
//
// Ecouter sur 127.0.0.1 ne suffit pas. Une page web malveillante ouverte dans le
// navigateur peut atteindre ce port par DNS rebinding: elle fait pointer un
// domaine qu'elle controle vers 127.0.0.1, et son code parle alors au serveur
// local comme s'il etait chez elle. Deux verrous independants s'y opposent.
//
// L'en-tete Host doit designer cette machine. Une requete rebondie porte le
// domaine de l'attaquant, elle est refusee avant tout traitement.
//
// Chaque requete doit porter le jeton de session, tire au hasard a chaque
// lancement et transmis par le lien affiche dans le terminal. Il passe une fois
// dans l'adresse, puis vit dans un cookie HttpOnly et SameSite=Strict, que le
// navigateur n'envoie ni a une autre origine ni depuis un autre site.

const (
	// sessionCookie porte le jeton une fois la session ouverte.
	sessionCookie = "quaero_session"
	// tokenParam porte le jeton dans le lien d'ouverture.
	tokenParam = "t"
)

// NewToken tire un jeton de session de 256 bits. Il ne vit qu'en memoire, le
// temps d'une execution: rien n'est ecrit sur le disque.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SessionURL rend le lien qui ouvre la session. Une ecoute sur toutes les
// interfaces s'ouvre depuis cette machine par 127.0.0.1.
func SessionURL(addr, token string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/?" + tokenParam + "=" + token
	}
	if isWildcard(host) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/?" + tokenParam + "=" + token
}

// ListensEverywhere dit si addr ecoute sur toutes les interfaces, auquel cas le
// controle de Host n'a plus de sens et seul le jeton protege l'interface.
func ListensEverywhere(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && isWildcard(host)
}

func isWildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

// allowedHosts liste les valeurs de Host acceptees pour addr. nil signifie
// "pas de controle" (ecoute sur toutes les interfaces, le jeton reste exige).
// Une adresse illisible n'autorise rien: on ferme plutot que d'ouvrir.
func allowedHosts(addr string) map[string]bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return map[string]bool{}
	}
	if isWildcard(host) {
		return nil
	}
	set := map[string]bool{}
	add := func(h string) {
		set[strings.ToLower(net.JoinHostPort(h, port))] = true
		// Sur le port 80, le navigateur omet le port dans Host.
		if port == "80" {
			if strings.Contains(h, ":") {
				set["["+strings.ToLower(h)+"]"] = true
			} else {
				set[strings.ToLower(h)] = true
			}
		}
	}
	add(host)
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		add("127.0.0.1")
		add("localhost")
		add("::1")
	}
	return set
}

// guard applique les deux verrous avant de passer la main.
type guard struct {
	token   string
	allowed map[string]bool
	next    http.Handler
}

func (g guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Sans jeton configure, rien ne passe: un oubli au demarrage ne doit pas
	// ouvrir l'interface a tout le monde.
	if g.token == "" {
		http.Error(w, "session non initialisee", http.StatusInternalServerError)
		return
	}
	if g.allowed != nil && !g.allowed[strings.ToLower(r.Host)] {
		http.Error(w, "hote refuse", http.StatusForbidden)
		return
	}

	// Ouverture: le jeton arrive dans l'adresse, il est echange contre le
	// cookie puis retire de l'adresse. La redirection va toujours a la racine,
	// jamais vers un chemin fourni par la requete.
	if t := r.URL.Query().Get(tokenParam); t != "" {
		if !sameToken(t, g.token) {
			deny(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    g.token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie(sessionCookie)
	if err != nil || !sameToken(c.Value, g.token) {
		deny(w, r)
		return
	}
	g.next.ServeHTTP(w, r)
}

// sameToken compare en temps constant, pour ne rien laisser deviner du jeton a
// qui mesurerait les temps de reponse.
func sameToken(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// deny refuse une requete sans session valide, en JSON pour l'API et en texte
// pour la page, sans rien dire du jeton attendu.
func deny(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session non reconnue"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("Session non reconnue. Ouvre le lien affiche dans le terminal ou Quaero a demarre.\n"))
}

// setSecurityHeaders pose les en-tetes de defense en profondeur. La page ne
// charge rien d'exterieur: la politique de contenu n'autorise que ses propres
// scripts et styles en ligne et ses appels a sa propre API.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
			"connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// Aucune adresse locale ne part vers les sites ouverts depuis la page.
	h.Set("Referrer-Policy", "no-referrer")
}
