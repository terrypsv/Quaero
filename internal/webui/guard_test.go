// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rawServer rend le gestionnaire sans session pre-ouverte ni Host pose
// d'avance, pour attaquer les verrous directement.
func rawServer() http.Handler {
	return (&Server{Client: &fakeSearcher{}, Version: "test", Token: testToken, Addr: testAddr}).Handler()
}

// req simule la page ouverte: le cookie pour la page, le meme jeton en en-tete
// pour l'API.
func req(target, host, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = host
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		r.Header.Set(sessionHeader, cookie)
	}
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, r)
	return rec
}

func TestDNSRebindingRefuse(t *testing.T) {
	// Un domaine qui pointe vers 127.0.0.1 reste un autre Host: refuse, meme
	// avec le bon cookie.
	for _, p := range []string{"/", "/api/version", "/fonts/" + polices[0]} {
		if rec := req(p, "evil.example:7777", testToken); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, attendu 403", p, rec.Code)
		}
	}
}

func TestSansSessionRefuse(t *testing.T) {
	if rec := req("/", testAddr, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("page: code = %d, attendu 401", rec.Code)
	}
	rec := req("/api/search?q=yaml", testAddr, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("api: code = %d, attendu 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("l'API refuse en JSON, obtenu %q", rec.Header().Get("Content-Type"))
	}
	// Meme les polices: sans session, rien n'est servi.
	if rec := req("/fonts/"+polices[0], testAddr, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("polices: code = %d, attendu 401", rec.Code)
	}
}

func TestMauvaisCookieRefuse(t *testing.T) {
	if rec := req("/api/version", testAddr, "devine"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, attendu 401", rec.Code)
	}
}

func TestOuvertureDeSession(t *testing.T) {
	rec := req("/?t="+testToken, testAddr, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, attendu 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/#t="+testToken {
		t.Errorf("redirection = %q, attendu /#t=<jeton>: la requete sans jeton, la page avec", loc)
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
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie HttpOnly=%v SameSite=%v Path=%q, attendu HttpOnly, Strict et /", c.HttpOnly, c.SameSite, c.Path)
	}
}

func TestMauvaisJetonNOuvrePas(t *testing.T) {
	rec := req("/?t=devine", testAddr, "")
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
	rec := req("//evil.example/?t="+testToken, testAddr, "")
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/#") {
		t.Errorf("redirection = %q, attendu la racine", loc)
	}
}

// Un cookie ne distingue pas les ports: tout autre serveur de 127.0.0.1 le
// recoit et pourrait le rejouer. Il ouvre la page, jamais l'API, qui exige
// le jeton en en-tete.
func TestCookieSeulNOuvrePasLAPI(t *testing.T) {
	for _, p := range []string{"/api/version", "/api/scan", "/api/search?q=yaml"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		r.Host = testAddr
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
		rec := httptest.NewRecorder()
		rawServer().ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s avec le seul cookie: code = %d, attendu 401", p, rec.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testAddr
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("page avec le cookie: code = %d, attendu 200", rec.Code)
	}
	// Et l'en-tete seul n'ouvre pas la page: il ne vient que de la page
	// elle-meme, deja ouverte.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testAddr
	r.Header.Set(sessionHeader, testToken)
	rec = httptest.NewRecorder()
	rawServer().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("page avec le seul en-tete: code = %d, attendu 401", rec.Code)
	}
}

func TestSessionValideServie(t *testing.T) {
	if rec := req("/api/version", testAddr, testToken); rec.Code != http.StatusOK {
		t.Fatalf("code = %d, attendu 200", rec.Code)
	}
}

func TestLocalhostEtIPv6Acceptes(t *testing.T) {
	for _, host := range []string{"localhost:7777", "[::1]:7777", "LOCALHOST:7777"} {
		if rec := req("/api/version", host, testToken); rec.Code != http.StatusOK {
			t.Errorf("%s: code = %d, attendu 200", host, rec.Code)
		}
	}
}

func TestSansJetonConfigureToutEstRefuse(t *testing.T) {
	// Un oubli au demarrage ferme l'interface, il ne l'ouvre pas: meme un
	// cookie vide ne passe pas.
	h := (&Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr}).Handler()
	for _, cookie := range []string{"", " "} {
		r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
		r.Host = testAddr
		r.Header.Set("Cookie", sessionCookie+"="+cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK {
			t.Fatalf("cookie %q: servi alors qu'aucun jeton n'est configure", cookie)
		}
	}
}

func TestEnTetesDeSecurite(t *testing.T) {
	// Poses meme sur un refus.
	for _, rec := range []*httptest.ResponseRecorder{
		req("/", testAddr, testToken), req("/", testAddr, ""), req("/", "evil.example:7777", ""),
	} {
		h := rec.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("code %d: CSP = %q", rec.Code, h.Get("Content-Security-Policy"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("code %d: en-tetes incomplets: %v", rec.Code, h)
		}
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

func TestURLs(t *testing.T) {
	if got := URL("127.0.0.1:7777"); got != "http://127.0.0.1:7777/" {
		t.Errorf("URL = %q", got)
	}
	if got := URL("0.0.0.0:7777"); got != "http://127.0.0.1:7777/" {
		t.Errorf("toutes interfaces: URL = %q", got)
	}
	if got := SessionURL("127.0.0.1:7777", "abc"); got != "http://127.0.0.1:7777/?t=abc" {
		t.Errorf("SessionURL = %q", got)
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
