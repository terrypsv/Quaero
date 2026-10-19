// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/reports"
)

func reportServer(t *testing.T) (*Server, http.Handler, *fakeScan) {
	t.Helper()
	f := newFakeScan()
	s := &Server{Client: &fakeSearcher{}, Version: "test", Addr: testAddr, Token: testToken,
		Scan: f.scan, Reports: &reports.Store{Dir: t.TempDir()}}
	return s, withSession(s.Handler()), f
}

func postJSON(h http.Handler, target, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

type listReply struct {
	Available bool            `json:"available"`
	Reports   []reports.Entry `json:"reports"`
}

func listOf(t *testing.T, h http.Handler) listReply {
	t.Helper()
	var out listReply
	if err := json.Unmarshal(get(h, "/api/reports").Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Une analyse finie ne laisse rien sur la machine tant qu'on ne l'enregistre
// pas. Enregistree, elle se rouvre et donne ses brouillons sans nouvelle
// analyse.
func TestAnalyseEnregistreeEtRouverte(t *testing.T) {
	s, h, f := reportServer(t)
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}}, ourOrigin)
	close(f.release)
	wait(t, s)
	job := decode(t, get(h, "/api/scan")).Job
	if job.Saved != "" {
		t.Fatalf("rapport enregistre sans qu'on le demande: %+v", job)
	}
	if n := len(listOf(t, h).Reports); n != 0 {
		t.Fatalf("%d rapports avant d'enregistrer", n)
	}
	if rec := get(h, "/api/scan/save?id="+job.ID); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("enregistrer en GET: %d", rec.Code)
	}
	if rec := post(h, "/api/scan/save", url.Values{"id": {job.ID}}, "http://127.0.0.1:8080"); rec.Code != http.StatusForbidden {
		t.Errorf("enregistrer depuis une autre origine: %d", rec.Code)
	}
	if rec := post(h, "/api/scan/save", url.Values{"id": {"autre"}}, ourOrigin); rec.Code != http.StatusNotFound {
		t.Errorf("enregistrer une autre analyse: %d", rec.Code)
	}
	rec := post(h, "/api/scan/save", url.Values{"id": {job.ID}}, ourOrigin)
	job = decode(t, rec).Job
	if rec.Code != http.StatusOK || job == nil || job.Saved == "" || job.SaveError != "" {
		t.Fatalf("enregistrement: %d %s", rec.Code, rec.Body.String())
	}
	if again := decode(t, post(h, "/api/scan/save", url.Values{"id": {job.ID}}, ourOrigin)).Job; again == nil || again.Saved != job.Saved {
		t.Errorf("second enregistrement: %+v, attendu %s", again, job.Saved)
	}
	if again := decode(t, get(h, "/api/scan")).Job; again.Saved != job.Saved {
		t.Errorf("l'analyse ne dit pas qu'elle est enregistree: %+v", again)
	}
	defer func() {
		// Son rapport efface, l'analyse redevient a enregistrer.
		post(h, "/api/reports/delete", url.Values{"id": {job.Saved}}, ourOrigin)
		if again := decode(t, get(h, "/api/scan")).Job; again.Saved != "" {
			t.Errorf("analyse dite enregistree apres suppression de son rapport: %+v", again)
		}
	}()
	list := listOf(t, h)
	if !list.Available || len(list.Reports) != 1 || list.Reports[0].ID != job.Saved || list.Reports[0].Findings != 1 {
		t.Fatalf("liste %+v", list)
	}

	var view struct{ View scanView }
	if err := json.Unmarshal(get(h, "/api/reports/view?id="+job.Saved).Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	v := view.View
	if v.ID != "r:"+job.Saved || v.Repo != "mushorg/cowrie" || v.URL == "" || v.State != stateDone || len(v.Reportable) != 1 || v.Result == nil {
		t.Errorf("rapport rouvert: %+v", v)
	}
	rec = get(h, "/api/scan/advisory?id=r:"+job.Saved+"&finding=QRO-SEMGREP-regle-x-internal-a-go-12")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "github.com/mushorg/cowrie") {
		t.Errorf("brouillon depuis un rapport rouvert: %d %s", rec.Code, rec.Body.String())
	}

	// L'export lisible, de l'analyse comme du rapport rouvert, porte un nom
	// tire de la cible.
	for _, id := range []string{job.ID, "r:" + job.Saved} {
		var out struct{ Text, File string }
		rec = get(h, "/api/scan/export?id="+url.QueryEscape(id))
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK ||
			!strings.HasPrefix(out.Text, "# Rapport Quaero, mushorg/cowrie") || !strings.HasPrefix(out.File, "mushorg-cowrie_") {
			t.Errorf("export %s: %d %+v %v", id, rec.Code, out, err)
		}
	}
	if rec := get(h, "/api/scan/export?id=r:absent"); rec.Code != http.StatusNotFound {
		t.Errorf("export d'un rapport absent: %d", rec.Code)
	}
	if !strings.HasPrefix(job.Saved, "mushorg-cowrie_") {
		t.Errorf("nom du rapport %q", job.Saved)
	}
}

func TestImportEtSuppression(t *testing.T) {
	_, h, _ := reportServer(t)
	rep := finding.NewReport(finding.Tool{Name: "quaero", Version: "test"}, "h", map[string]any{"cible": `C:\Users\moi\projet`})
	rep.Add(finding.Finding{ID: "A", Title: "a", Severity: finding.SeverityLow, Status: finding.StatusReview})
	rep.Finish()
	data, _ := json.Marshal(rep)

	if rec := postJSON(h, "/api/reports/import", string(data), "http://127.0.0.1:8080"); rec.Code != http.StatusForbidden {
		t.Errorf("import depuis une autre origine: code %d, attendu 403", rec.Code)
	}
	if rec := postJSON(h, "/api/reports/import", "pas un rapport", ourOrigin); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pas_un_rapport") {
		t.Errorf("import invalide: %d %s", rec.Code, rec.Body.String())
	}
	rec := postJSON(h, "/api/reports/import", string(data), ourOrigin)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Report   reports.Entry
		Existing bool
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !reports.ValidID(out.Report.ID) || out.Existing {
		t.Fatalf("import: %+v", out)
	}
	// Le meme fichier, repris par exemple du dossier des rapports, rend celui
	// qui y est deja.
	var again struct {
		Report   reports.Entry
		Existing bool
	}
	_ = json.Unmarshal(postJSON(h, "/api/reports/import", string(data), ourOrigin).Body.Bytes(), &again)
	if again.Report.ID != out.Report.ID || !again.Existing {
		t.Errorf("second import du meme rapport: %+v", again)
	}

	var view struct{ View scanView }
	_ = json.Unmarshal(get(h, "/api/reports/view?id="+out.Report.ID).Body.Bytes(), &view)
	if !view.View.Local || view.View.URL != "" || view.View.Report != "" {
		t.Errorf("rapport local rouvert avec un lien GitHub: %+v", view.View)
	}

	if rec := post(h, "/api/reports/delete", url.Values{"id": {out.Report.ID}}, ourOrigin); rec.Code != http.StatusOK {
		t.Errorf("suppression: %d", rec.Code)
	}
	if rec := get(h, "/api/reports/view?id="+out.Report.ID); rec.Code != http.StatusNotFound {
		t.Errorf("rapport efface encore lisible: %d", rec.Code)
	}
	if rec := post(h, "/api/reports/delete", url.Values{"id": {out.Report.ID}}, ourOrigin); rec.Code != http.StatusNotFound {
		t.Errorf("seconde suppression: %d, attendu 404", rec.Code)
	}
	if n := len(listOf(t, h).Reports); n != 0 {
		t.Errorf("%d rapports listes apres suppression", n)
	}
}

// Un nom de rapport qui n'est pas tire par Quaero ne touche pas au disque.
func TestRapportNomRefuse(t *testing.T) {
	_, h, _ := reportServer(t)
	for _, id := range []string{"../config", "..%2Fconfig", "x"} {
		if rec := get(h, "/api/reports/view?id="+id); rec.Code != http.StatusNotFound {
			t.Errorf("%s: code %d", id, rec.Code)
		}
		if rec := post(h, "/api/reports/delete", url.Values{"id": {id}}, ourOrigin); rec.Code != http.StatusNotFound {
			t.Errorf("suppression %s: code %d", id, rec.Code)
		}
	}
	if rec := get(h, "/api/scan/advisory?id=r:../config&finding=x"); rec.Code != http.StatusNotFound {
		t.Errorf("brouillon depuis un nom refuse: %d", rec.Code)
	}
}

func TestRapportsIndisponibles(t *testing.T) {
	_, h := scanServer(newFakeScan().scan)
	if got := listOf(t, h); got.Available || len(got.Reports) != 0 {
		t.Errorf("sans dossier de rapports: %+v", got)
	}
	if rec := postJSON(h, "/api/reports/import", "{}", ourOrigin); rec.Code != http.StatusNotImplemented {
		t.Errorf("import sans dossier: %d", rec.Code)
	}
	if rec := post(h, "/api/scan/save", url.Values{"id": {"x"}}, ourOrigin); rec.Code != http.StatusNotImplemented {
		t.Errorf("enregistrer sans dossier: %d", rec.Code)
	}
}

// La case cochee avant de lancer garde le rapport des la fin de l'analyse,
// sans autre geste.
func TestEnregistrementChoisiAvant(t *testing.T) {
	s, h, f := reportServer(t)
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}, "enregistrer": {"1"}}, ourOrigin)
	close(f.release)
	wait(t, s)
	job := decode(t, get(h, "/api/scan")).Job
	if job.Saved == "" || job.SaveError != "" {
		t.Fatalf("rapport non garde malgre la case: %+v", job)
	}
	list := listOf(t, h)
	if len(list.Reports) != 1 || list.Reports[0].ID != job.Saved {
		t.Errorf("liste %+v", list)
	}
	// Le bouton apres coup ne range pas une seconde copie.
	if again := decode(t, post(h, "/api/scan/save", url.Values{"id": {job.ID}}, ourOrigin)).Job; again == nil || again.Saved != job.Saved {
		t.Errorf("bouton apres la case: %+v", again)
	}
	if n := len(listOf(t, h).Reports); n != 1 {
		t.Errorf("%d rapports, attendu 1", n)
	}
}

// Le bouton ouvre le dossier des rapports, et lui seul: aucun chemin ne vient
// de la requete. Sans ouvreur, ou en GET, rien ne s'ouvre.
func TestOuvrirLeDossier(t *testing.T) {
	s, h, _ := reportServer(t)
	s.Reports.Dir = filepath.Join(s.Reports.Dir, "pas-encore-cree")
	var opened []string
	s.OpenDir = func(dir string) error { opened = append(opened, dir); return nil }
	h = withSession(s.Handler())

	var list struct {
		Open bool `json:"open"`
	}
	if err := json.Unmarshal(get(h, "/api/reports").Body.Bytes(), &list); err != nil || !list.Open {
		t.Fatalf("bouton non propose: %v %+v", err, list)
	}
	if rec := get(h, "/api/reports/open"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	rec := post(h, "/api/reports/open", url.Values{"dir": {`C:\Windows`}}, ourOrigin)
	if rec.Code != http.StatusOK || len(opened) != 1 || opened[0] != s.Reports.Dir {
		t.Fatalf("ouverture: %d %v", rec.Code, opened)
	}
	if info, err := os.Stat(s.Reports.Dir); err != nil || !info.IsDir() {
		t.Errorf("dossier non cree avant ouverture: %v", err)
	}
	if rec := post(h, "/api/reports/open", nil, "http://ailleurs.example"); rec.Code == http.StatusOK || len(opened) != 1 {
		t.Errorf("autre origine: %d %v", rec.Code, opened)
	}

	s.OpenDir = nil
	h = withSession(s.Handler())
	if rec := post(h, "/api/reports/open", nil, ourOrigin); rec.Code != http.StatusNotImplemented {
		t.Errorf("sans ouvreur: %d", rec.Code)
	}
}

// Une analyse se compare a la precedente enregistree du meme depot, et un
// rapport rouvert a celle d'avant lui.
func TestComparaisonAvecLaPrecedente(t *testing.T) {
	s, h, f := reportServer(t)
	close(f.release)
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}, "enregistrer": {"1"}}, ourOrigin)
	wait(t, s)
	first := decode(t, get(h, "/api/scan")).Job
	if first.Saved == "" || first.Diff == nil || first.Diff.Previous != "" {
		t.Fatalf("premiere analyse: %+v", first)
	}
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}}, ourOrigin)
	wait(t, s)
	second := decode(t, get(h, "/api/scan")).Job
	if d := second.Diff; d == nil || d.Previous != first.Saved || d.Unchanged != 1 || len(d.New) != 0 || len(d.Fixed) != 0 {
		t.Fatalf("seconde analyse: %+v", second.Diff)
	}
	var out struct{ Text string }
	if err := json.Unmarshal(get(h, "/api/scan/export?id="+second.ID).Body.Bytes(), &out); err != nil ||
		!strings.Contains(out.Text, "## Depuis l'analyse précédente") || !strings.Contains(out.Text, "Rien de corrigé ni de nouveau.") {
		t.Errorf("export: %v\n%s", err, out.Text)
	}
	var view struct{ View scanView }
	if err := json.Unmarshal(get(h, "/api/reports/view?id="+first.Saved).Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if d := view.View.Diff; d == nil || d.Previous != "" {
		t.Errorf("rapport rouvert, rien avant lui: %+v", d)
	}
}
