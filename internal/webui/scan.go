// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/repo"
)

// L'onglet audit lance l'analyse d'un depot public nomme a la main. Les
// garde-fous sont ceux de la ligne de commande, plus ceux d'une interface web:
//
//   - la cible est un depot github.com et rien d'autre. L'interface n'analyse
//     jamais un chemin local: ce serait offrir a une requete le choix d'un
//     dossier de la machine;
//   - une seule analyse a la fois, annulable. Une seconde demande est refusee,
//     pas mise en file: lancer n'est jamais un effet de bord;
//   - les routes qui lancent ou annulent n'acceptent que POST, derriere le
//     garde de session et le controle d'origine (guard.go);
//   - le rapport et le brouillon restent en memoire, dans ce processus. Rien
//     n'est envoye: le signalement se depose a la main.

// Etapes annoncees par une ScanFunc pendant son travail.
const (
	StageClone   = "clone"
	StageAnalyse = "analyse"
)

// Etats d'une analyse terminee, et celui d'une annulation en cours.
const (
	stateDone      = "fini"
	stateFailed    = "echec"
	stateCanceled  = "annule"
	stateCanceling = "annulation"
)

// ScanFunc clone et analyse le depot ref, en annoncant chaque etape par stage.
// Elle s'arrete des que ctx est annule et ne laisse rien sur le disque.
type ScanFunc func(ctx context.Context, ref repo.Ref, stage func(string)) (*finding.Report, error)

// scanJob est une analyse, en cours ou terminee.
type scanJob struct {
	id        string
	ref       repo.Ref
	state     string
	canceling bool
	started   time.Time
	ended     time.Time
	err       string
	report    *finding.Report
	cancel    context.CancelFunc
	done      chan struct{}
}

func (j *scanJob) running() bool { return j.ended.IsZero() }

// scanJobs garde l'analyse courante, ou la derniere terminee.
type scanJobs struct {
	mu  sync.Mutex
	cur *scanJob
	// closed refuse toute nouvelle analyse une fois l'arret demande: un clone
	// lance pendant la fermeture survivrait au processus.
	closed bool
}

// errClosing dit qu'une analyse est refusee parce que Quaero s'arrete.
var errClosing = errors.New("quaero s'arrete")

// scanView est ce que la page recoit d'une analyse.
type scanView struct {
	ID      string  `json:"id"`
	Repo    string  `json:"repo"`
	URL     string  `json:"url"`
	Report  string  `json:"report_url"`
	State   string  `json:"state"`
	Running bool    `json:"running"`
	Elapsed float64 `json:"elapsed_s"`
	Error   string  `json:"error,omitempty"`
	// Result n'est rendu qu'une fois l'analyse finie.
	Result *finding.Report `json:"report,omitempty"`
	// Reportable liste les constats qui peuvent devenir un signalement: ceux
	// du code et des dependances, pas ceux sur le scan lui-meme.
	Reportable []string `json:"reportable,omitempty"`
}

// view lit j sous le verrou de scanJobs.
func (j *scanJob) view(now time.Time) scanView {
	end := now
	if !j.running() {
		end = j.ended
	}
	v := scanView{
		ID:      j.id,
		Repo:    j.ref.String(),
		URL:     j.ref.URL(),
		Report:  j.ref.ReportURL(),
		State:   j.state,
		Running: j.running(),
		Elapsed: math.Round(end.Sub(j.started).Seconds()*10) / 10,
		Error:   j.err,
	}
	if j.running() && j.canceling {
		v.State = stateCanceling
	}
	if j.report != nil {
		v.Result = j.report
		v.Reportable = []string{}
		for _, f := range advisory.Candidates(j.report) {
			v.Reportable = append(v.Reportable, f.ID)
		}
	}
	return v
}

// start lance une analyse si aucune ne tourne. Elle rend l'analyse lancee, ou
// celle qui tourne deja et false, ou errClosing si Quaero s'arrete.
func (s *scanJobs) start(scan ScanFunc, ref repo.Ref) (*scanJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errClosing
	}
	if s.cur != nil && s.cur.running() {
		return s.cur, false, nil
	}
	// L'analyse ne depend pas de la requete qui l'a lancee: fermer l'onglet ne
	// l'arrete pas, le bouton annuler si.
	ctx, cancel := context.WithCancel(context.Background())
	job := &scanJob{
		id:      newJobID(),
		ref:     ref,
		state:   StageClone,
		started: time.Now(),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	s.cur = job
	go func() {
		defer cancel()
		rep, err := scan(ctx, ref, func(stage string) { s.stage(job, stage) })
		s.finish(job, rep, err, ctx.Err())
	}()
	return job, true, nil
}

// stage note l'etape annoncee, tant que l'analyse tourne et n'est pas en cours
// d'annulation.
func (s *scanJobs) stage(job *scanJob, stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.running() && !job.canceling {
		job.state = stage
	}
}

func (s *scanJobs) finish(job *scanJob, rep *finding.Report, err, ctxErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.ended = time.Now()
	switch {
	case ctxErr != nil:
		// Une analyse annulee ne rend rien: un resultat partiel passerait pour
		// un depot verifie.
		job.state = stateCanceled
	case err != nil:
		job.state = stateFailed
		job.err = err.Error()
	case rep == nil:
		job.state = stateFailed
		job.err = "analyse sans rapport"
	default:
		job.state = stateDone
		job.report = rep
	}
	close(job.done)
}

// stop annule l'analyse id si elle tourne encore.
func (s *scanJobs) stop(id string) (*scanJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.cur
	if job == nil || job.id != id || !job.running() {
		return job, false
	}
	job.canceling = true
	job.cancel()
	return job, true
}

// current rend la vue de l'analyse courante, ou nil.
func (s *scanJobs) current() *scanView {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	v := s.cur.view(time.Now())
	return &v
}

func (s *scanJobs) viewOf(job *scanJob) scanView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return job.view(time.Now())
}

// report rend le rapport de l'analyse id, si elle est finie.
func (s *scanJobs) report(id string) (*finding.Report, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || s.cur.id != id || s.cur.report == nil {
		return nil, false
	}
	return s.cur.report, true
}

// StopScan annule l'analyse en cours et attend qu'elle ait efface son clone,
// au plus timeout, puis refuse toute nouvelle analyse. A appeler avant de
// quitter, pour ne pas laisser de code tiers dans le dossier temporaire.
// stopped dit si une analyse tournait, finished si elle s'est terminee dans le
// delai.
func (s *Server) StopScan(timeout time.Duration) (stopped, finished bool) {
	if s.scans == nil {
		return false, true
	}
	s.scans.mu.Lock()
	s.scans.closed = true
	job := s.scans.cur
	if job == nil || !job.running() {
		s.scans.mu.Unlock()
		return false, true
	}
	job.canceling = true
	job.cancel()
	s.scans.mu.Unlock()
	select {
	case <-job.done:
		return true, true
	case <-time.After(timeout):
		return true, false
	}
}

// maxFormBytes borne le corps des requetes qui lancent ou annulent: une
// reference de depot tient en quelques dizaines d'octets.
const maxFormBytes = 4 << 10

// handleScan lance une analyse (POST) ou rend l'analyse courante (GET).
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		writeJSON(w, http.StatusOK, map[string]any{"available": s.Scan != nil, "job": s.scans.current()})
	case http.MethodPost:
		if s.Scan == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "analyse indisponible dans cette execution"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requete illisible"})
			return
		}
		ref, ok := repo.Parse(r.PostForm.Get("repo"))
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pas une reference de depot github (owner/repo ou URL github.com)"})
			return
		}
		job, started, err := s.scans.start(s.Scan, ref)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		if !started {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "une analyse est deja en cours", "job": s.scans.viewOf(job)})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": s.scans.viewOf(job)})
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "methode non permise"})
	}
}

// handleScanCancel annule l'analyse designee, si elle tourne encore.
func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "methode non permise"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requete illisible"})
		return
	}
	job, ok := s.scans.stop(r.PostForm.Get("id"))
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "aucune analyse en cours sous cet identifiant"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": s.scans.viewOf(job)})
}

// draftFileRe garde d'un identifiant de constat ce qui peut nommer un fichier.
var draftFileRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// handleScanAdvisory rend le brouillon de signalement d'un constat de la
// derniere analyse. Il ne fait que lire le rapport en memoire.
func (s *Server) handleScanAdvisory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "methode non permise"})
		return
	}
	q := r.URL.Query()
	rep, ok := s.scans.report(q.Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "aucun rapport pour cette analyse, relancer l'analyse"})
		return
	}
	f, err := advisory.Find(rep, q.Get("finding"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	name := draftFileRe.ReplaceAllString(f.ID, "-")
	if len(name) > 80 {
		name = name[:80]
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"draft": advisory.Draft(rep, f),
		"file":  "signalement-" + name + ".md",
	})
}

func newJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000")))
	}
	return hex.EncodeToString(b)
}
