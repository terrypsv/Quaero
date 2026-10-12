// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rawServer rend le gestionnaire sans Host pose d'avance, pour attaquer le
// garde directement.
func rawServer() http.Handler {
	return (&Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr}).Handler()
}

func get(target, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = host
	rec := httptest.NewRecorder()
	rawServer().ServeHTTP(rec, r)
	return rec
}

func TestDNSRebindingRefuse(t *testing.T) {
	// Un domaine qui pointe vers 127.0.0.1 reste un autre Host: refuse.
	for _, p := range []string{"/", "/api/version", "/fonts/" + polices[0]} {
		if rec := get(p, "evil.example:7777"); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, attendu 403", p, rec.Code)
		}
	}
}

func TestPageServieSansJeton(t *testing.T) {
	if rec := get("/", testAddr); rec.Code != http.StatusOK {
		t.Fatalf("code = %d, attendu 200", rec.Code)
	}
}

func TestLocalhostEtIPv6Acceptes(t *testing.T) {
	for _, host := range []string{"localhost:7777", "[::1]:7777", "LOCALHOST:7777"} {
		if rec := get("/api/version", host); rec.Code != http.StatusOK {
			t.Errorf("%s: code = %d, attendu 200", host, rec.Code)
		}
	}
}

func TestEnTetesDeSecurite(t *testing.T) {
	// Poses meme sur un refus.
	for _, host := range []string{testAddr, "evil.example:7777"} {
		h := get("/", host).Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", host, h.Get("Content-Security-Policy"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: en-tetes incomplets: %v", host, h)
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
		t.Error("toutes interfaces: pas de controle de Host")
	}
	lan := allowedHosts("192.168.1.10:7777")
	if !lan["192.168.1.10:7777"] || lan["localhost:7777"] {
		t.Errorf("adresse precise: seule elle-meme est acceptee, obtenu %v", lan)
	}
	if got := allowedHosts("pas une adresse"); got == nil || len(got) != 0 {
		t.Errorf("adresse illisible: rien n'est accepte, obtenu %v", got)
	}
}

func TestURL(t *testing.T) {
	if got := URL("127.0.0.1:7777"); got != "http://127.0.0.1:7777/" {
		t.Errorf("URL = %q", got)
	}
	if got := URL("0.0.0.0:7777"); got != "http://127.0.0.1:7777/" {
		t.Errorf("toutes interfaces: URL = %q", got)
	}
}
