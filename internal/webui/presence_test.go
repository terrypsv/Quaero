// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Le jeton est tire une fois, garde, puis repris au lancement suivant.
func TestJetonGardeEtRepris(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".quaero", "session")
	first, reused, err := SessionToken(path)
	if err != nil || reused || !tokenRe.MatchString(first) {
		t.Fatalf("premier lancement: %q %v %v", first, reused, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("droits du fichier: %v %v", info.Mode().Perm(), err)
		}
	}
	again, reused, err := SessionToken(path)
	if err != nil || !reused || again != first {
		t.Errorf("relance: %q %v %v, attendu %q repris", again, reused, err, first)
	}
}

// Un fichier abime ou lisible par d'autres n'est pas repris.
func TestJetonNonRepris(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session")
	if err := os.WriteFile(path, []byte("pas un jeton\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, reused, err := SessionToken(path)
	if err != nil || reused || !tokenRe.MatchString(tok) {
		t.Errorf("fichier abime: %q %v %v", tok, reused, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	other, reused, err := SessionToken(path)
	if err != nil || reused || other == tok {
		t.Errorf("fichier lisible par d'autres repris: %v %v", reused, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("fichier reecrit en %v", info.Mode().Perm())
	}
}

// Seul un appel de la session compte comme un onglet present.
func TestPresence(t *testing.T) {
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr, Token: testToken}
	h := s.Handler()
	if s.WaitPresence(20 * time.Millisecond) {
		t.Fatal("presence sans aucun onglet")
	}
	r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r.Host = testAddr
	r.Header.Set(sessionHeader, "autre-jeton")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if s.WaitPresence(20 * time.Millisecond) {
		t.Error("un mauvais jeton compte comme un onglet")
	}
	withSession(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if !s.WaitPresence(time.Second) {
		t.Error("l'onglet de la session n'est pas vu")
	}
}

// La requete de presence reste ouverte, puis se ferme sans rien rendre.
func TestPresenceTenue(t *testing.T) {
	old := presenceHold
	presenceHold = 50 * time.Millisecond
	defer func() { presenceHold = old }()
	_, h := scanServer(nil)

	start := time.Now()
	rec := get(h, "/api/presence")
	if rec.Code != http.StatusNoContent || time.Since(start) < 40*time.Millisecond {
		t.Errorf("presence: %d apres %v", rec.Code, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/presence", nil).WithContext(ctx))
	if rec.Code != http.StatusNoContent {
		t.Errorf("onglet ferme: %d", rec.Code)
	}
	if rec := post(h, "/api/presence", nil, ourOrigin); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("presence en POST: %d", rec.Code)
	}
}
