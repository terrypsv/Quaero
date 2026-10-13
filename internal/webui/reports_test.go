// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	var out struct{ Report reports.Entry }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !reports.ValidID(out.Report.ID) {
		t.Fatalf("identifiant %q", out.Report.ID)
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
