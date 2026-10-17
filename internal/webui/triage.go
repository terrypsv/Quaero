// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"errors"
	"net/http"

	"github.com/terrypsv/Quaero/internal/triage"
)

// Le tri des constats: chaque analyse et chaque rapport rouvert arrivent avec
// les decisions deja prises sur le meme depot (internal/triage). La page en
// pose de nouvelles par POST /api/triage. Le pre-tri par regles, lui, voyage
// dans le rapport (preuves « contexte », internal/codescan/pretri.go).

// triageFormBytes borne la requete: une note de 500 caracteres, encodee.
const triageFormBytes = 16 << 10

// withTriage joint a v les decisions qui s'appliquent a ses constats.
func (s *Server) withTriage(v scanView) scanView {
	if s.Triage != nil && v.Result != nil {
		v.Triage = s.Triage.For(v.Result)
	}
	return v
}

// handleTriage enregistre la decision prise sur un constat de l'analyse en
// cours ou d'un rapport rouvert.
func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if s.Triage == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "tri indisponible dans cette execution"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, triageFormBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requete illisible"})
		return
	}
	st, ok := triage.ParseState(r.PostForm.Get("etat"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "etat de tri inconnu"})
		return
	}
	rep, ok := s.reportFor(r.PostForm.Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "aucun rapport pour cette analyse, relancer l'analyse"})
		return
	}
	id := r.PostForm.Get("finding")
	d, err := s.Triage.Set(rep, id, st, r.PostForm.Get("note"))
	switch {
	case errors.Is(err, triage.ErrUnknownFinding):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, triage.ErrNoTarget), errors.Is(err, triage.ErrFull):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "decision non enregistree: " + err.Error()})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"finding": id, "tri": d})
	}
}
