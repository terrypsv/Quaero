// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/terrypsv/Quaero/internal/triage"
)

const triFinding = "QRO-SEMGREP-regle-x-internal-a-go-12"

// Une decision prise sur une analyse revient avec la suivante, avec un
// rapport rouvert, et se defait.
func TestTriGardeEntreAnalyses(t *testing.T) {
	s, h, f := reportServer(t)
	s.Triage = &triage.Store{Path: filepath.Join(t.TempDir(), "tri.json")}
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}, "enregistrer": {"1"}}, ourOrigin)
	close(f.release)
	wait(t, s)
	job := decode(t, get(h, "/api/scan")).Job
	if len(job.Triage) != 0 {
		t.Fatalf("decision avant tout tri: %+v", job.Triage)
	}

	if rec := post(h, "/api/triage", url.Values{"id": {job.ID}, "finding": {triFinding}, "etat": {"faux_positif"}}, "http://127.0.0.1:8080"); rec.Code != http.StatusForbidden {
		t.Errorf("tri depuis une autre origine: %d", rec.Code)
	}
	if rec := get(h, "/api/triage"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("tri en GET: %d", rec.Code)
	}
	for _, bad := range []url.Values{
		{"id": {job.ID}, "finding": {triFinding}, "etat": {"efface"}},
		{"id": {job.ID}, "finding": {"absent"}, "etat": {"confirme"}},
		{"id": {"autre"}, "finding": {triFinding}, "etat": {"confirme"}},
		{"id": {job.ID}, "finding": {"QRO-SCAN-ABSENT-gosec"}, "etat": {"confirme"}},
	} {
		if rec := post(h, "/api/triage", bad, ourOrigin); rec.Code == http.StatusOK {
			t.Errorf("tri accepte: %v", bad)
		}
	}

	rec := post(h, "/api/triage", url.Values{"id": {job.ID}, "finding": {triFinding}, "etat": {"faux_positif"}, "note": {"requete preparee plus haut"}}, ourOrigin)
	var out struct {
		Finding string
		Tri     triage.Decision
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Tri.State != triage.FalsePositive || out.Tri.Note != "requete preparee plus haut" {
		t.Fatalf("tri: %d %s", rec.Code, rec.Body.String())
	}
	if got := decode(t, get(h, "/api/scan")).Job.Triage[triFinding]; got.State != triage.FalsePositive {
		t.Errorf("analyse sans sa decision: %+v", got)
	}

	// Le rapport rouvert, et une nouvelle analyse du meme depot, la portent.
	var view struct{ View scanView }
	_ = json.Unmarshal(get(h, "/api/reports/view?id="+job.Saved).Body.Bytes(), &view)
	if view.View.Triage[triFinding].State != triage.FalsePositive {
		t.Errorf("rapport rouvert sans la decision: %+v", view.View.Triage)
	}
	f2 := newFakeScan()
	s.Scan = f2.scan
	post(h, "/api/scan", url.Values{"cible": {"mushorg/cowrie"}}, ourOrigin)
	close(f2.release)
	wait(t, s)
	if got := decode(t, get(h, "/api/scan")).Job.Triage[triFinding]; got.State != triage.FalsePositive {
		t.Errorf("nouvelle analyse sans la decision: %+v", got)
	}

	// Depuis le rapport rouvert, on remet a verifier: partout.
	post(h, "/api/triage", url.Values{"id": {"r:" + job.Saved}, "finding": {triFinding}, "etat": {"a_verifier"}}, ourOrigin)
	if got := decode(t, get(h, "/api/scan")).Job.Triage; len(got) != 0 {
		t.Errorf("decision non defaite: %+v", got)
	}
}

func TestTriIndisponible(t *testing.T) {
	_, h := scanServer(newFakeScan().scan)
	var reply struct{ Triage bool }
	_ = json.Unmarshal(get(h, "/api/scan").Body.Bytes(), &reply)
	if reply.Triage {
		t.Error("tri annonce sans magasin")
	}
	if rec := post(h, "/api/triage", url.Values{"id": {"x"}, "finding": {"y"}, "etat": {"confirme"}}, ourOrigin); rec.Code != http.StatusNotImplemented {
		t.Errorf("tri sans magasin: %d", rec.Code)
	}
}
