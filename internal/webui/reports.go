// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/repo"
	"github.com/terrypsv/Quaero/internal/reports"
)

// Un rapport n'est garde sur la machine que si l'utilisateur le demande: une
// analyse de passage ne laisse rien. Les rapports enregistres se rouvrent sans
// reseau: la liste, la lecture, le brouillon de signalement et l'export ne
// demandent rien a GitHub ni aux moteurs. Un rapport importe est une donnee,
// la page l'echappe comme le reste et seul son schema est controle (voir
// reports.Parse).

// errNoReport dit qu'il n'y a pas, ou plus, de rapport a enregistrer pour
// cette analyse: une autre l'a remplacee, ou elle n'a pas fini.
var errNoReport = errors.New("aucun rapport pour cette analyse, relancer l'analyse")

// save enregistre une fois le rapport de l'analyse id, finie. Un second appel
// rend le meme rapport, l'ecriture se fait hors du verrou.
func (s *scanJobs) save(id string, store *reports.Store) (scanView, error) {
	s.mu.Lock()
	job := s.cur
	if job == nil || job.id != id || job.report == nil {
		s.mu.Unlock()
		return scanView{}, errNoReport
	}
	if job.savedID != "" || job.saving {
		v := job.view(time.Now())
		s.mu.Unlock()
		return v, nil
	}
	job.saving = true
	rep := job.report
	s.mu.Unlock()

	e, err := store.Save(rep)

	s.mu.Lock()
	defer s.mu.Unlock()
	job.saving = false
	if err != nil {
		job.saveErr = err.Error()
		return job.view(time.Now()), err
	}
	job.savedID, job.saveErr = e.ID, ""
	return job.view(time.Now()), nil
}

// forget retire le lien entre l'analyse courante et le rapport id, efface:
// elle redevient a enregistrer.
func (s *scanJobs) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && id != "" && s.cur.savedID == id {
		s.cur.savedID = ""
	}
}

// handleScanSave enregistre, a la demande, le rapport de la derniere analyse.
func (s *Server) handleScanSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if s.Reports == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "rapports indisponibles dans cette execution"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requete illisible"})
		return
	}
	v, err := s.scans.save(r.PostForm.Get("id"), s.Reports)
	switch {
	case errors.Is(err, errNoReport):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "rapport non enregistre: " + err.Error(), "job": v})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"job": v})
	}
}

// reportFor rend le rapport designe par la page: l'analyse courante, ou un
// rapport enregistre (prefixe r:).
func (s *Server) reportFor(id string) (*finding.Report, bool) {
	if saved, ok := strings.CutPrefix(id, savedPrefix); ok {
		if s.Reports == nil {
			return nil, false
		}
		rep, err := s.Reports.Load(saved)
		return rep, err == nil
	}
	return s.scans.report(id)
}

// savedView presente un rapport enregistre comme une analyse finie, pour que
// la page l'affiche, le filtre et en tire des brouillons de la meme facon.
func savedView(id string, rep *finding.Report) scanView {
	label, _ := rep.Run.Context["cible"].(string)
	if label == "" {
		label, _ = rep.Run.Context["path"].(string)
	}
	v := scanView{
		ID:         savedPrefix + id,
		Repo:       label,
		State:      stateDone,
		Result:     rep,
		Reportable: reportableIDs(rep),
		Saved:      id,
	}
	if ref, ok := repo.Parse(label); ok && strings.HasPrefix(strings.ToLower(label), "github.com/") {
		v.Repo, v.URL, v.Report = ref.String(), ref.URL(), ref.ReportURL()
	} else {
		v.Local = true
	}
	if !rep.Run.FinishedAt.IsZero() {
		at := rep.Run.FinishedAt
		v.SavedAt = &at
		if !rep.Run.StartedAt.IsZero() {
			v.Elapsed = math.Round(at.Sub(rep.Run.StartedAt).Seconds()*10) / 10
		}
	}
	return v
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "methode non permise"})
}

// handleReports liste les rapports enregistres.
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	if s.Reports == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reports": []reports.Entry{}})
		return
	}
	list, err := s.Reports.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dossier des rapports illisible"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "dir": s.Reports.Dir, "reports": list})
}

// handleReportView rouvre un rapport enregistre.
func (s *Server) handleReportView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	id := r.URL.Query().Get("id")
	if s.Reports == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": reports.ErrNotFound.Error()})
		return
	}
	rep, err := s.Reports.Load(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": reports.ErrNotFound.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"view": savedView(id, rep)})
}

// handleReportImport enregistre un rapport envoye par la page, lu depuis un
// fichier -scan-json choisi par l'utilisateur.
func (s *Server) handleReportImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if s.Reports == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "rapports indisponibles dans cette execution"})
		return
	}
	// Un import a la fois: chacun peut tenir 20 Mo en memoire le temps d'etre lu.
	if !s.importing.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "un import est deja en cours", "code": "occupe"})
		return
	}
	defer s.importing.Store(false)
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, reports.MaxBytes+1))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "rapport trop gros", "code": "trop_gros"})
		return
	}
	e, existing, err := s.Reports.Import(data)
	switch {
	case errors.Is(err, reports.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "code": "pas_un_rapport"})
		return
	case errors.Is(err, reports.ErrTooBig):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error(), "code": "trop_gros"})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rapport non enregistre: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": e, "existing": existing})
}

// handleReportDelete efface un rapport enregistre.
func (s *Server) handleReportDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requete illisible"})
		return
	}
	if s.Reports == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": reports.ErrNotFound.Error()})
		return
	}
	id := r.PostForm.Get("id")
	err := s.Reports.Delete(id)
	if err == nil || errors.Is(err, reports.ErrNotFound) {
		s.scans.forget(id)
	}
	if errors.Is(err, reports.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "suppression impossible: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
