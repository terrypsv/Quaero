// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"net"
	"net/http"
	"strings"
)

// Le garde protege l'interface locale contre le DNS rebinding, sans rien
// demander a celui qui l'utilise.
//
// Ecouter sur 127.0.0.1 ne suffit pas. Une page web malveillante ouverte dans le
// navigateur peut atteindre ce port en faisant pointer un domaine qu'elle
// controle vers 127.0.0.1: son code parle alors au serveur local comme s'il
// etait chez elle. Une telle requete porte le domaine de l'attaquant dans son
// en-tete Host, elle est refusee avant tout traitement.
//
// La session par jeton (lien du terminal, cookie HttpOnly) est retiree pour
// l'instant et reviendra avant la premiere version publiee, voir ROADMAP.

// ListensEverywhere dit si addr ecoute sur toutes les interfaces, auquel cas le
// controle de Host n'a plus de sens et plus rien ne protege l'interface.
func ListensEverywhere(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && isWildcard(host)
}

func isWildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

// URL rend l'adresse a ouvrir dans le navigateur. Une ecoute sur toutes les
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

// allowedHosts liste les valeurs de Host acceptees pour addr. nil signifie
// "pas de controle" (ecoute sur toutes les interfaces). Une adresse illisible
// n'autorise rien: on ferme plutot que d'ouvrir.
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

// guard controle l'hote avant de passer la main.
type guard struct {
	allowed map[string]bool
	next    http.Handler
}

func (g guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if g.allowed != nil && !g.allowed[strings.ToLower(r.Host)] {
		http.Error(w, "hote refuse", http.StatusForbidden)
		return
	}
	g.next.ServeHTTP(w, r)
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
