// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed" // page de session embarquee
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

// Le garde protege l'interface locale par deux verrous independants.
//
// Ecouter sur 127.0.0.1 ne suffit pas. Une page web malveillante ouverte dans le
// navigateur peut atteindre ce port par DNS rebinding: elle fait pointer un
// domaine qu'elle controle vers 127.0.0.1, et son code parle alors au serveur
// local comme s'il etait chez elle.
//
// L'en-tete Host doit designer cette machine. Une requete rebondie porte le
// domaine de l'attaquant, elle est refusee avant tout traitement.
//
// Chaque requete doit porter le jeton de session, tire au hasard a chaque
// lancement. Quaero ouvre lui-meme le navigateur sur le lien qui le porte, le
// jeton passe une fois dans l'adresse, puis vit a deux endroits.
//
// Un cookie HttpOnly et SameSite=Strict ouvre la page et ses polices. Il ne
// suffit pas pour l'API: un cookie ne distingue pas les ports, le navigateur
// l'envoie aussi a tout autre serveur de 127.0.0.1, qui pourrait le rejouer.
//
// L'API exige le jeton dans l'en-tete X-Quaero-Session. La page le garde dans
// son stockage local, propre a son origine, port compris: aucun autre serveur
// de la machine ne le voit passer. Une page d'un autre site ne peut pas non
// plus poser cet en-tete sans une autorisation CORS que Quaero ne donne
// jamais. Lire un rapport, chercher ou lancer une analyse demande donc le
// jeton lui-meme, pas seulement le cookie.

const (
	// sessionCookie porte le jeton une fois la session ouverte.
	sessionCookie = "quaero_session"
	// tokenParam porte le jeton dans le lien d'ouverture.
	tokenParam = "t"
	// sessionHeader porte le jeton dans chaque appel a l'API.
	sessionHeader = "X-Quaero-Session"
)

//go:embed session.html
var sessionHTML []byte

// NewToken tire un jeton de session de 256 bits. Il ne vit qu'en memoire, le
// temps d'une execution: rien n'est ecrit sur le disque.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

// URL rend l'adresse de l'interface, sans jeton. Une ecoute sur toutes les
// interfaces s'ouvre depuis cette machine par 127.0.0.1.
func URL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	if isWildcard(host) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// SessionURL rend le lien qui ouvre la session: l'adresse de l'interface et le
// jeton de cette execution.
func SessionURL(addr, token string) string {
	return URL(addr) + "?" + tokenParam + "=" + token
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
	// cookie, et la page le recoit dans le fragment de la redirection, qui ne
	// repart jamais vers un serveur. Elle le range puis l'efface de l'adresse.
	// La redirection va toujours a la racine, jamais vers un chemin fourni par
	// la requete.
	if t := r.URL.Query().Get(tokenParam); t != "" {
		if !sameToken(t, g.token) {
			deny(w, r)
			return
		}
		// Pas de Secure: l'interface ne sert que du HTTP sur la boucle locale,
		// et un cookie Secure n'y serait pas renvoye. Le cookie ne quitte pas
		// la machine, HttpOnly et SameSite=Strict le gardent de la page et des
		// autres sites.
		// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    g.token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/#"+tokenParam+"="+g.token, http.StatusSeeOther)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		if !sameToken(r.Header.Get(sessionHeader), g.token) {
			deny(w, r)
			return
		}
	} else if c, err := r.Cookie(sessionCookie); err != nil || !sameToken(c.Value, g.token) {
		deny(w, r)
		return
	}
	// Ce qui modifie un etat (lancer, annuler) doit venir de la page elle-meme.
	// SameSite=Strict ne distingue pas les ports: une page servie sur un autre
	// port de cette machine est du meme site et le cookie l'accompagne. Son
	// origine, elle, differe. Le navigateur pose Origin sur tout POST.
	if !safeMethod(r.Method) && !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origine refusee"})
		return
	}
	g.next.ServeHTTP(w, r)
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// sameOrigin dit si une requete qui modifie un etat vient de l'interface. Sans
// en-tete Origin, la requete ne vient pas d'une page (un client en ligne de
// commande qui a le cookie a deja la session); avec, il doit designer l'hote
// meme qui repond.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	return strings.EqualFold(o, "http://"+r.Host)
}

// sameToken compare en temps constant, pour ne rien laisser deviner du jeton a
// qui mesurerait les temps de reponse.
func sameToken(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// deny refuse une requete sans session valide, en JSON pour l'API et avec une
// page qui dit quoi faire pour le reste, sans rien dire du jeton attendu.
func deny(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session non reconnue, relancer Quaero"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	// Page embarquee dans le binaire (go:embed), sans donnee venue de la
	// requete: il n'y a rien a echapper.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(sessionHTML)
}

// setSecurityHeaders pose les en-tetes de defense en profondeur. La page ne
// charge rien d'exterieur: la politique de contenu n'autorise que ses propres
// scripts et styles en ligne, ses polices embarquees et ses appels a sa propre
// API.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
			"connect-src 'self'; img-src 'self' data:; font-src 'self'; "+
			"base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// Aucune adresse locale ne part vers les sites ouverts depuis la page.
	h.Set("Referrer-Policy", "no-referrer")
}
