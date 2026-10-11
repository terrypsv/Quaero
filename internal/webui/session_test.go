// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rawServer rend le gestionnaire sans session pre-ouverte, pour attaquer les
// verrous directement.
func rawServer() http.Handler {
	return (&Server{Client: &fakeSearcher{}, Version: "test", Token: testToken, Addr: testAddr}).Handler()
}

func req(method, target, host, cookie string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	return r
}

func TestDNSRebindingRefuse(t *testing.T) {
	// Un domaine qui pointe vers 127.0.0.1 reste un autre Host: refuse, meme
	// avec le bon cookie.
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/api/version", "evil.example:7777", testToken))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, attendu 403", rec.Code)
	}
}

func TestSansSessionRefuse(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/", testAddr, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("page: code = %d, attendu 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/api/search?q=yaml", testAddr, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("api: code = %d, attendu 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("l'API refuse en JSON, obtenu %q", rec.Header().Get("Content-Type"))
	}
}

func TestMauvaisCookieRefuse(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/api/version", testAddr, "devine"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, attendu 401", rec.Code)
	}
}

func TestOuvertureDeSession(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/?t="+testToken, testAddr, ""))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, attendu 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("redirection = %q, attendu / pour retirer le jeton de l'adresse", loc)
	}
	var c *http.Cookie
	for _, k := range rec.Result().Cookies() {
		if k.Name == sessionCookie {
			c = k
		}
	}
	if c == nil {
		t.Fatal("cookie de session absent")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie HttpOnly=%v SameSite=%v, attendu HttpOnly et Strict", c.HttpOnly, c.SameSite)
	}
}

func TestMauvaisJetonNOuvrePas(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/?t=devine", testAddr, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, attendu 401", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("aucun cookie ne doit etre pose pour un mauvais jeton")
	}
}

func TestRedirectionJamaisDetournee(t *testing.T) {
	// Meme avec le bon jeton, un chemin comme //evil.example ne doit pas
	// devenir une redirection vers un autre site.
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "//evil.example/?t="+testToken, testAddr, ""))
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("redirection = %q, attendu /", loc)
	}
}

func TestSessionValideServie(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/api/version", testAddr, testToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, attendu 200", rec.Code)
	}
}

func TestLocalhostEtIPv6Acceptes(t *testing.T) {
	for _, host := range []string{"localhost:7777", "[::1]:7777", "LOCALHOST:7777"} {
		rec := httptest.NewRecorder()
		rawServer().ServeHTTP(rec, req(http.MethodGet, "/api/version", host, testToken))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: code = %d, attendu 200", host, rec.Code)
		}
	}
}

func TestSansJetonConfigureToutEstRefuse(t *testing.T) {
	// Un oubli au demarrage ferme l'interface, il ne l'ouvre pas: meme un
	// cookie vide ne passe pas.
	h := (&Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr}).Handler()
	for _, cookie := range []string{"", " "} {
		r := req(http.MethodGet, "/api/version", testAddr, "")
		r.Header.Set("Cookie", sessionCookie+"="+cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK {
			t.Fatalf("cookie %q: servi alors qu'aucun jeton n'est configure", cookie)
		}
	}
}

func TestEnTetesDeSecurite(t *testing.T) {
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, req(http.MethodGet, "/", testAddr, testToken))
	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("en-tetes incomplets: %v", h)
	}
}

func TestAllowedHosts(t *testing.T) {
	loop := allowedHosts("127.0.0.1:7777")
	for _, h := range []string{"127.0.0.1:7777", "localhost:7777", "[::1]:7777"} {
		if !loop[h] {
			t.Errorf("%s devrait etre accepte en boucle locale", h)
		}
	}
	if loop["127.0.0.1:8080"] {
		t.Error("un autre port ne doit pas etre accepte")
	}
	if allowedHosts("0.0.0.0:7777") != nil {
		t.Error("toutes interfaces: pas de controle de Host, le jeton reste exige")
	}
	lan := allowedHosts("192.168.1.10:7777")
	if !lan["192.168.1.10:7777"] || lan["localhost:7777"] {
		t.Errorf("adresse precise: seule elle-meme est acceptee, obtenu %v", lan)
	}
	if got := allowedHosts("pas une adresse"); got == nil || len(got) != 0 {
		t.Errorf("adresse illisible: rien n'est accepte, obtenu %v", got)
	}
}

func TestSessionURL(t *testing.T) {
	if got := SessionURL("127.0.0.1:7777", "abc"); got != "http://127.0.0.1:7777/?t=abc" {
		t.Errorf("SessionURL = %q", got)
	}
	if got := SessionURL("0.0.0.0:7777", "abc"); got != "http://127.0.0.1:7777/?t=abc" {
		t.Errorf("toutes interfaces: SessionURL = %q", got)
	}
}

func TestNewTokenAleatoire(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if len(a) != 64 || a == b {
		t.Errorf("jetons %q et %q: attendu 64 caracteres hexadecimaux, differents", a, b)
	}
}
