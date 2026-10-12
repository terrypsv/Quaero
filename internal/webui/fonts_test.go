// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var polices = []string{"jetbrains-mono.woff2", "syne.woff2", "archivo-quaero.woff2"}

// Les polices sont produites par scripts/polices.py puis versionnees. Un
// binaire sans elles s'afficherait avec celles du systeme, sans que rien ne
// le signale: le test le signale.
func TestPolicesEmbarquees(t *testing.T) {
	for _, name := range polices {
		data, err := fontFiles.ReadFile("fonts/" + name)
		if err != nil {
			t.Errorf("%s absente du binaire: lancer python scripts/polices.py", name)
			continue
		}
		if !bytes.HasPrefix(data, []byte("wOF2")) {
			t.Errorf("%s n'est pas un fichier woff2", name)
		}
	}
	for _, lic := range []string{"OFL-JetBrainsMono.txt", "OFL-Syne.txt", "OFL-Archivo.txt"} {
		if _, err := fontFiles.ReadFile("fonts/" + lic); err != nil {
			t.Errorf("licence %s absente: les polices OFL voyagent avec leur licence", lic)
		}
	}
}

func TestPoliceServie(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fonts/"+polices[0], nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, attendu 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("Content-Type = %q, attendu font/woff2", ct)
	}
}

// Seuls les .woff2 du dossier sortent: ni les licences, ni les sommes de
// controle, ni rien en dehors du dossier.
func TestPoliceRefusee(t *testing.T) {
	for _, p := range []string{
		"/fonts/", "/fonts/OFL-Syne.txt", "/fonts/SHA256SUMS", "/fonts/LISEZMOI.md",
		"/fonts/inconnue.woff2", "/fonts/sous/jetbrains-mono.woff2", "/fonts/..%2fserver.go",
	} {
		rec := httptest.NewRecorder()
		newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s servi, attendu un refus", p)
		}
	}
}

func TestPoliceSousSession(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/fonts/"+polices[0], testAddr, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, attendu 401 sans session", rec.Code)
	}
}

func TestCSPAutoriseLesPolicesLocales(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&fakeSearcher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self'") {
		t.Errorf("CSP = %q, font-src 'self' attendu", csp)
	}
}

// Sans session, le navigateur recoit une page qui dit quoi faire. L'API garde
// sa reponse JSON (voir TestSansSessionRefuse).
func TestPageSessionEnHTML(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/", testAddr, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, attendu 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, attendu text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Session") || !strings.Contains(rec.Body.String(), "terminal") {
		t.Error("la page doit dire d'ouvrir le lien du terminal")
	}
}

// Rien d'exterieur dans les pages: la politique de contenu le bloquerait de
// toute facon, mais une page qui en depend s'afficherait cassee.
func TestPagesSansRessourceExterieure(t *testing.T) {
	externe := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?https?:|url\(\s*["']?https?:|@import`)
	for name, page := range map[string][]byte{"index.html": indexHTML, "session.html": sessionHTML} {
		if loc := externe.FindIndex(page); loc != nil {
			t.Errorf("%s charge une ressource exterieure: %q", name, page[loc[0]:loc[1]+20])
		}
	}
}
