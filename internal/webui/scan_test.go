// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
)

// fakeScan est une analyse sans clone ni moteur. Elle annonce ses etapes, puis
// attend d'etre liberee ou annulee.
type fakeScan struct {
	mu      sync.Mutex
	calls   []string
	release chan struct{}
	err     error
}

func newFakeScan() *fakeScan { return &fakeScan{release: make(chan struct{})} }

func (f *fakeScan) scan(ctx context.Context, t ScanTarget, stage func(string)) (*finding.Report, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t.Label())
	f.mu.Unlock()
	if !t.Local() {
		stage(StageClone)
	}
	stage(StageAnalyse)
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	cible := t.Label()
	if !t.Local() {
		cible = "github.com/" + cible
	}
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "hote", map[string]any{
		"mode": "codescan", "cible": cible, "commit": strings.Repeat("a", 40),
	})
	rep.Add(finding.Finding{
		ID: "QRO-SEMGREP-regle-x-internal-a-go-12", Title: "Requete SQL construite par concatenation",
		Category: "code", Severity: finding.SeverityHigh, Status: finding.StatusReview,
		Target:   &finding.Target{Type: "file", Identifier: "internal/a.go:12"},
		Declared: finding.Bool(false),
	})
	rep.Add(finding.Finding{
		ID: "QRO-SCAN-ABSENT-gosec", Title: "Analyseur non disponible: gosec",
		Category: "code", Severity: finding.SeverityInfo, Status: finding.StatusReview,
	})
	rep.Finish()
	return rep, nil
}

func (f *fakeScan) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// scanServer rend le serveur, pour l'attendre ou l'arreter, et son
// gestionnaire avec une session ouverte.
func scanServer(scan ScanFunc) (*Server, http.Handler) {
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr, Token: testToken, Scan: scan}
	return s, withSession(s.Handler())
}

func post(h http.Handler, target string, form url.Values, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func get(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

type jobReply struct {
	Available bool      `json:"available"`
	Error     string    `json:"error"`
	Job       *scanView `json:"job"`
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) jobReply {
	t.Helper()
	var out jobReply
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("reponse illisible: %v: %s", err, rec.Body.String())
	}
	return out
}

// wait attend la fin de l'analyse courante.
func wait(t *testing.T, s *Server) {
	t.Helper()
	s.scans.mu.Lock()
	job := s.scans.cur
	s.scans.mu.Unlock()
	if job == nil {
		t.Fatal("aucune analyse lancee")
	}
	select {
	case <-job.done:
	case <-time.After(5 * time.Second):
		t.Fatal("analyse jamais terminee")
	}
}

const ourOrigin = "http://" + testAddr

func TestAnalyseLanceeEtFinie(t *testing.T) {
	f := newFakeScan()
	s, h := scanServer(f.scan)

	rec := post(h, "/api/scan", url.Values{"cible": {"https://github.com/mushorg/cowrie.git"}}, ourOrigin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("lancement: code = %d: %s", rec.Code, rec.Body.String())
	}
	job := decode(t, rec).Job
	if job == nil || job.Repo != "mushorg/cowrie" || !job.Running || job.ID == "" {
		t.Fatalf("analyse lancee: %+v", job)
	}
	if job.Report != "https://github.com/mushorg/cowrie/security/advisories/new" {
		t.Errorf("lien de signalement %q", job.Report)
	}

	// Une seule a la fois: la seconde demande est refusee, pas mise en file.
	rec = post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin)
	if rec.Code != http.StatusConflict {
		t.Fatalf("seconde analyse: code = %d, attendu 409", rec.Code)
	}
	if other := decode(t, rec).Job; other == nil || other.ID != job.ID {
		t.Errorf("le refus doit montrer l'analyse en cours: %+v", other)
	}

	close(f.release)
	wait(t, s)
	got := decode(t, get(h, "/api/scan"))
	if !got.Available || got.Job == nil || got.Job.State != stateDone || got.Job.Running {
		t.Fatalf("apres la fin: %+v", got.Job)
	}
	if got.Job.Result == nil || len(got.Job.Result.Findings) != 2 {
		t.Fatalf("rapport absent ou incomplet: %+v", got.Job.Result)
	}
	// Seul le constat de code peut devenir un signalement, pas le moteur absent.
	if len(got.Job.Reportable) != 1 || got.Job.Reportable[0] != "QRO-SEMGREP-regle-x-internal-a-go-12" {
		t.Errorf("signalables = %v", got.Job.Reportable)
	}
	if f.count() != 1 {
		t.Errorf("%d analyses lancees, attendu 1", f.count())
	}
}

// Une cible est un depot github.com ou le chemin complet d'un dossier qui
// existe. Ni autre hote, ni chemin relatif, ni racine, ni fichier, ni rien qui
// ressemble a une option.
func TestAnalyseCibleRefusee(t *testing.T) {
	f := newFakeScan()
	_, h := scanServer(f.scan)
	file := filepath.Join(t.TempDir(), "fichier.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.VolumeName(file) + string(filepath.Separator)
	for _, target := range []string{
		"", ".", "..", "../secret", "dossier/relatif/en/trop", "gitlab.com/a/b",
		"file:///etc/passwd", "--upload-pack=x/y", "a/b/c",
		root, file, filepath.Join(t.TempDir(), "absent"),
	} {
		rec := post(h, "/api/scan", url.Values{"cible": {target}}, ourOrigin)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: code = %d, attendu 400", target, rec.Code)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d analyses lancees pour des cibles refusees", f.count())
	}
}

// Un dossier de la machine nomme en entier est lu sur place: pas de clone, pas
// de lien GitHub.
func TestAnalyseDossierLocal(t *testing.T) {
	f := newFakeScan()
	s, h := scanServer(f.scan)
	dir := t.TempDir()
	rec := post(h, "/api/scan", url.Values{"cible": {dir + string(filepath.Separator)}}, ourOrigin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body.String())
	}
	job := decode(t, rec).Job
	real, _ := filepath.EvalSymlinks(dir)
	if !job.Local || job.Repo != real || job.URL != "" || job.Report != "" || job.State != StageAnalyse {
		t.Errorf("analyse locale: %+v", job)
	}
	close(f.release)
	wait(t, s)
	if got := decode(t, get(h, "/api/scan")).Job; got.State != stateDone || got.Result == nil {
		t.Errorf("apres la fin: %+v", got)
	}
}

func TestParseTarget(t *testing.T) {
	if got, err := ParseTarget("  https://github.com/mushorg/cowrie.git "); err != nil || got.Local() || got.Label() != "mushorg/cowrie" {
		t.Errorf("depot: %+v, %v", got, err)
	}
	dir := t.TempDir()
	real, _ := filepath.EvalSymlinks(dir)
	if got, err := ParseTarget(dir); err != nil || !got.Local() || got.Label() != real {
		t.Errorf("dossier: %+v, %v", got, err)
	}
	// Un lien vers la racine reste une racine.
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "vers-racine")
		if err := os.Symlink("/", link); err == nil {
			if _, err := ParseTarget(link); err != errRootDir {
				t.Errorf("lien vers la racine: %v, attendu %v", err, errRootDir)
			}
		}
	}
	for in, want := range map[string]error{
		`\\serveur\partage\projet`:                            errNetPath,
		"//serveur/partage":                                   errNetPath,
		"pas une cible":                                       errNoTarget,
		filepath.Join(dir, "absent"):                          errNoDir,
		filepath.VolumeName(dir) + string(filepath.Separator): errRootDir,
	} {
		if _, err := ParseTarget(in); err != want {
			t.Errorf("%q: %v, attendu %v", in, err, want)
		}
	}
}

func TestAnalyseAnnulee(t *testing.T) {
	f := newFakeScan()
	s, h := scanServer(f.scan)
	job := decode(t, post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin)).Job

	if rec := post(h, "/api/scan/cancel", url.Values{"id": {"autre"}}, ourOrigin); rec.Code != http.StatusConflict {
		t.Errorf("annulation d'une autre analyse: code = %d, attendu 409", rec.Code)
	}
	rec := post(h, "/api/scan/cancel", url.Values{"id": {job.ID}}, ourOrigin)
	if rec.Code != http.StatusOK {
		t.Fatalf("annulation: code = %d: %s", rec.Code, rec.Body.String())
	}
	wait(t, s)
	got := decode(t, get(h, "/api/scan")).Job
	if got.State != stateCanceled || got.Result != nil {
		t.Errorf("apres annulation: etat %q, rapport %v", got.State, got.Result != nil)
	}
	// Une analyse finie ne s'annule plus.
	if rec := post(h, "/api/scan/cancel", url.Values{"id": {job.ID}}, ourOrigin); rec.Code != http.StatusConflict {
		t.Errorf("annulation apres la fin: code = %d, attendu 409", rec.Code)
	}
	// Et la suivante peut partir.
	if rec := post(h, "/api/scan", url.Values{"cible": {"a/c"}}, ourOrigin); rec.Code != http.StatusAccepted {
		t.Errorf("relance apres annulation: code = %d", rec.Code)
	}
	s.StopScan(5 * time.Second)
}

func TestAnalyseEnEchec(t *testing.T) {
	f := newFakeScan()
	f.err = context.DeadlineExceeded
	s, h := scanServer(f.scan)
	post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin)
	close(f.release)
	wait(t, s)
	got := decode(t, get(h, "/api/scan")).Job
	if got.State != stateFailed || got.Error == "" || got.Result != nil {
		t.Errorf("echec: %+v", got)
	}
}

// Quitter Quaero arrete l'analyse et attend qu'elle ait fini.
func TestStopScanAttendLaFin(t *testing.T) {
	f := newFakeScan()
	s, h := scanServer(f.scan)
	post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin)
	if stopped, finished := s.StopScan(5 * time.Second); !stopped || !finished {
		t.Errorf("StopScan = %v, %v, attendu true, true", stopped, finished)
	}
	got := decode(t, get(h, "/api/scan")).Job
	if got.Running || got.State != stateCanceled {
		t.Errorf("apres StopScan: %+v", got)
	}
	// Sans analyse en cours, StopScan rend la main aussitot.
	if stopped, _ := s.StopScan(time.Second); stopped {
		t.Error("StopScan sur une analyse deja finie")
	}
	// Une fois l'arret demande, plus aucune analyse ne part: son clone
	// survivrait au processus.
	if rec := post(h, "/api/scan", url.Values{"cible": {"a/c"}}, ourOrigin); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("analyse pendant l'arret: code = %d, attendu 503", rec.Code)
	}
	if f.count() != 1 {
		t.Errorf("%d analyses lancees, attendu 1", f.count())
	}
	if stopped, _ := (&Server{}).StopScan(time.Second); stopped {
		t.Error("StopScan sans analyse")
	}
}

func TestBrouillonDeSignalement(t *testing.T) {
	f := newFakeScan()
	s, h := scanServer(f.scan)
	job := decode(t, post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}}, ourOrigin)).Job

	// Pas de brouillon tant que l'analyse tourne.
	if rec := get(h, "/api/scan/advisory?id="+job.ID+"&finding=x"); rec.Code != http.StatusNotFound {
		t.Errorf("brouillon pendant l'analyse: code = %d, attendu 404", rec.Code)
	}
	close(f.release)
	wait(t, s)

	rec := get(h, "/api/scan/advisory?id="+job.ID+"&finding=QRO-SEMGREP-regle-x-internal-a-go-12")
	if rec.Code != http.StatusOK {
		t.Fatalf("brouillon: code = %d: %s", rec.Code, rec.Body.String())
	}
	var d struct{ Draft, File string }
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Requete SQL construite", "github.com/mushorg/cowrie", "internal/a.go:12", "BROUILLON NON VERIFIE"} {
		if !strings.Contains(d.Draft, want) {
			t.Errorf("brouillon sans %q", want)
		}
	}
	if d.File != "signalement-QRO-SEMGREP-regle-x-internal-a-go-12.md" {
		t.Errorf("nom de fichier %q", d.File)
	}

	// Un constat sur le scan lui-meme, un constat inconnu ou une autre analyse
	// ne donnent pas de brouillon.
	for _, q := range []string{
		"id=" + job.ID + "&finding=QRO-SCAN-ABSENT-gosec",
		"id=" + job.ID + "&finding=inconnu",
		"id=autre&finding=QRO-SEMGREP-regle-x-internal-a-go-12",
	} {
		if rec := get(h, "/api/scan/advisory?"+q); rec.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, attendu 404", q, rec.Code)
		}
	}
}

// Lancer et annuler ne passent que par POST, et le brouillon que par GET.
func TestAnalyseMethodes(t *testing.T) {
	_, h := scanServer(newFakeScan().scan)
	for _, c := range []struct{ method, target string }{
		{http.MethodPut, "/api/scan"},
		{http.MethodDelete, "/api/scan"},
		{http.MethodGet, "/api/scan/cancel"},
		{http.MethodPost, "/api/scan/advisory"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.target, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: code = %d, attendu 405", c.method, c.target, rec.Code)
		}
	}
}

// Une page servie sur un autre port de cette machine est du meme site: le
// cookie l'accompagne, mais son origine la trahit.
func TestAnalyseAutreOrigineRefusee(t *testing.T) {
	f := newFakeScan()
	_, h := scanServer(f.scan)
	for _, origin := range []string{"http://127.0.0.1:8080", "http://evil.example", "null"} {
		if rec := post(h, "/api/scan", url.Values{"cible": {"a/b"}}, origin); rec.Code != http.StatusForbidden {
			t.Errorf("origine %s: code = %d, attendu 403", origin, rec.Code)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d analyses lancees depuis une autre origine", f.count())
	}
}

// A l'ecoute de tout le reseau, un dossier local est refuse: la page peut
// venir d'une autre machine.
func TestDossierLocalRefuseSurToutesInterfaces(t *testing.T) {
	f := newFakeScan()
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: "0.0.0.0:7777", Token: testToken, Scan: f.scan}
	h := withSession(s.Handler())
	rec := post(h, "/api/scan", url.Values{"cible": {t.TempDir()}}, "")
	if rec.Code != http.StatusBadRequest || f.count() != 0 {
		t.Errorf("code = %d, %d analyse(s)", rec.Code, f.count())
	}
}

func TestAnalyseIndisponible(t *testing.T) {
	_, h := scanServer(nil)
	if got := decode(t, get(h, "/api/scan")); got.Available || got.Job != nil {
		t.Errorf("sans ScanFunc: %+v", got)
	}
	if rec := post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin); rec.Code != http.StatusNotImplemented {
		t.Errorf("code = %d, attendu 501", rec.Code)
	}
}

// Sans session, l'analyse ne part pas, et la reponse est du JSON.
func TestAnalyseSansSession(t *testing.T) {
	f := newFakeScan()
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr, Token: testToken, Scan: f.scan}
	r := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader("repo=a/b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = testAddr
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || f.count() != 0 {
		t.Errorf("code = %d, %d analyse(s)", rec.Code, f.count())
	}
}

type codedErr struct{ code string }

func (e codedErr) Error() string { return "echec " + e.code }
func (e codedErr) Code() string  { return e.code }

// Un echec code garde son code jusqu'a la page, qui le dit avec ses mots.
func TestEchecCode(t *testing.T) {
	f := newFakeScan()
	f.err = codedErr{"jeton_sans_acces"}
	s, h := scanServer(f.scan)
	post(h, "/api/scan", url.Values{"cible": {"a/b"}}, ourOrigin)
	close(f.release)
	wait(t, s)
	got := decode(t, get(h, "/api/scan")).Job
	if got.State != stateFailed || got.ErrorCode != "jeton_sans_acces" || got.Error != "echec jeton_sans_acces" {
		t.Errorf("echec: %+v", got)
	}
}

// La page recoit les limites de l'audit, comme elle recoit le quota.
func TestLimitesDAnalyse(t *testing.T) {
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr, Token: testToken,
		Scan: newFakeScan().scan, ScanTimeout: 15 * time.Minute}
	rec := get(withSession(s.Handler()), "/api/scan")
	var out struct {
		Limits struct {
			Concurrent int `json:"concurrent"`
			Timeout    int `json:"engine_timeout_s"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Limits.Concurrent != 1 || out.Limits.Timeout != 900 {
		t.Errorf("limites %+v", out.Limits)
	}
}
