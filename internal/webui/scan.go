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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/repo"
	"github.com/terrypsv/Quaero/internal/reports"
)

// L'onglet audit lance l'analyse d'une cible nommee a la main. Les garde-fous
// sont ceux de la ligne de commande, plus ceux d'une interface web:
//
//   - la cible est un depot github.com, clone puis efface, ou le chemin complet
//     d'un dossier de la machine, lu sur place. Un dossier se nomme en entier:
//     un chemin relatif dependrait du dossier ou Quaero a ete lance, et une
//     racine de disque n'est pas un projet;
//   - seul le detenteur de la session peut nommer une cible: le cookie de
//     session et le controle d'origine (guard.go) ecartent toute autre page;
//   - une seule analyse a la fois, annulable. Une seconde demande est refusee,
//     pas mise en file: lancer n'est jamais un effet de bord;
//   - les routes qui lancent ou annulent n'acceptent que POST, derriere le
//     garde de session et le controle d'origine (guard.go);
//   - le rapport et le brouillon restent en memoire, dans ce processus. Le
//     rapport n'est garde sur la machine que si l'utilisateur le demande, en
//     cochant la case avant l'analyse ou par le bouton apres (reports.go).
//     Rien n'est envoye: le signalement se depose a la main.

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

// ScanTarget est ce que l'on analyse: un depot GitHub, ou un dossier local.
type ScanTarget struct {
	// Repo est le depot GitHub a cloner, quand Dir est vide.
	Repo repo.Ref
	// Dir est le chemin complet d'un dossier de la machine, lu sur place.
	Dir string
}

// Local dit si la cible est un dossier de la machine.
func (t ScanTarget) Local() bool { return t.Dir != "" }

// Label nomme la cible pour la page et le rapport.
func (t ScanTarget) Label() string {
	if t.Local() {
		return t.Dir
	}
	return t.Repo.String()
}

// Erreurs de lecture d'une cible, dites a la page telles quelles.
var (
	errNoTarget = errors.New("ni un depot github (owner/repo ou URL github.com), ni le chemin complet d'un dossier")
	errNoDir    = errors.New("dossier introuvable")
	errNotDir   = errors.New("ce chemin n'est pas un dossier")
	errRootDir  = errors.New("une racine de disque ne s'analyse pas, nommer le dossier du projet")
	errNetPath  = errors.New("un chemin reseau ne s'analyse pas d'ici, copier le projet sur la machine")
	errLocalOff = errors.New("dossier local refuse: Quaero ecoute sur toutes les interfaces")
)

// targetErrorCode nomme une erreur de cible pour la page, qui la dit avec ses
// propres mots.
func targetErrorCode(err error) string {
	switch err {
	case errNoDir:
		return "dossier_absent"
	case errNotDir:
		return "pas_un_dossier"
	case errRootDir:
		return "racine"
	case errNetPath:
		return "reseau"
	case errLocalOff:
		return "local_ferme"
	}
	return "cible"
}

// ParseTarget lit ce qui est saisi dans l'onglet audit: un chemin complet est
// un dossier local, le reste doit etre une reference de depot GitHub.
//
// Un chemin reseau (\\serveur\partage) est refuse avant tout acces: sous
// Windows, le simple fait de le lire enverrait l'identite de l'utilisateur a
// ce serveur. Les liens symboliques sont resolus avant de juger, pour qu'un
// lien vers la racine ne passe pas pour un dossier de projet.
func ParseTarget(raw string) (ScanTarget, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, "//") {
		return ScanTarget{}, errNetPath
	}
	if filepath.IsAbs(raw) {
		dir, err := filepath.EvalSymlinks(filepath.Clean(raw))
		if err != nil {
			return ScanTarget{}, errNoDir
		}
		if filepath.Dir(dir) == dir {
			return ScanTarget{}, errRootDir
		}
		info, err := os.Stat(dir)
		if err != nil {
			return ScanTarget{}, errNoDir
		}
		if !info.IsDir() {
			return ScanTarget{}, errNotDir
		}
		return ScanTarget{Dir: dir}, nil
	}
	if ref, ok := repo.Parse(raw); ok {
		return ScanTarget{Repo: ref}, nil
	}
	return ScanTarget{}, errNoTarget
}

// ScanFunc analyse la cible t, en annoncant chaque etape par stage. Elle
// s'arrete des que ctx est annule et ne laisse aucun clone sur le disque.
type ScanFunc func(ctx context.Context, t ScanTarget, stage func(string)) (*finding.Report, error)

// scanJob est une analyse, en cours ou terminee.
type scanJob struct {
	id        string
	target    ScanTarget
	state     string
	canceling bool
	started   time.Time
	ended     time.Time
	err       string
	errCode   string
	report    *finding.Report
	savedID   string
	saveErr   string
	saving    bool
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
	ID string `json:"id"`
	// Repo nomme la cible: owner/repo, ou le chemin du dossier.
	Repo  string `json:"repo"`
	Local bool   `json:"local,omitempty"`
	// URL et Report ne valent que pour un depot GitHub.
	URL     string  `json:"url,omitempty"`
	Report  string  `json:"report_url,omitempty"`
	State   string  `json:"state"`
	Running bool    `json:"running"`
	Elapsed float64 `json:"elapsed_s"`
	Error   string  `json:"error,omitempty"`
	// ErrorCode nomme le cas d'echec, pour que la page le dise avec ses mots.
	ErrorCode string `json:"error_code,omitempty"`
	// Result n'est rendu qu'une fois l'analyse finie.
	Result *finding.Report `json:"report,omitempty"`
	// Reportable liste les constats qui peuvent devenir un signalement: ceux
	// du code et des dependances, pas ceux sur le scan lui-meme.
	Reportable []string `json:"reportable,omitempty"`
	// Saved nomme le rapport enregistre sur la machine a la demande de
	// l'utilisateur, SaveError dit pourquoi il ne l'a pas ete.
	Saved     string `json:"saved_id,omitempty"`
	SaveError string `json:"save_error,omitempty"`
	// SavedAt date un rapport rouvert.
	SavedAt *time.Time `json:"saved_at,omitempty"`
}

// view lit j sous le verrou de scanJobs.
func (j *scanJob) view(now time.Time) scanView {
	end := now
	if !j.running() {
		end = j.ended
	}
	v := scanView{
		ID:        j.id,
		Repo:      j.target.Label(),
		Local:     j.target.Local(),
		State:     j.state,
		Running:   j.running(),
		Elapsed:   math.Round(end.Sub(j.started).Seconds()*10) / 10,
		Error:     j.err,
		ErrorCode: j.errCode,
	}
	if !j.target.Local() {
		v.URL = j.target.Repo.URL()
		v.Report = j.target.Repo.ReportURL()
	}
	if j.running() && j.canceling {
		v.State = stateCanceling
	}
	if j.report != nil {
		v.Result = j.report
		v.Reportable = reportableIDs(j.report)
	}
	v.Saved, v.SaveError = j.savedID, j.saveErr
	return v
}

func reportableIDs(rep *finding.Report) []string {
	ids := []string{}
	for _, f := range advisory.Candidates(rep) {
		ids = append(ids, f.ID)
	}
	return ids
}

// savedPrefix distingue un rapport rouvert d'une analyse dans les identifiants
// que la page renvoie.
const savedPrefix = "r:"

// start lance une analyse si aucune ne tourne. Elle rend l'analyse lancee, ou
// celle qui tourne deja et false, ou errClosing si Quaero s'arrete.
// keep, s'il n'est pas nil, recoit le rapport des la fin de l'analyse: c'est
// la case « Enregistrer le rapport » cochee avant de lancer.
func (s *scanJobs) start(scan ScanFunc, t ScanTarget, keep *reports.Store) (*scanJob, bool, error) {
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
	first := StageClone
	if t.Local() {
		first = StageAnalyse
	}
	job := &scanJob{
		id:      newJobID(),
		target:  t,
		state:   first,
		started: time.Now(),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	s.cur = job
	go func() {
		defer cancel()
		rep, err := scan(ctx, t, func(stage string) { s.stage(job, stage) })
		// Demande avant l'analyse, l'enregistrement se fait avant de la dire
		// finie: fermer l'onglet entre-temps ne le perd pas. ctx.Err() est lu
		// une fois, une annulation pendant l'ecriture ne laisse pas une analyse
		// annulee avec un rapport garde.
		ctxErr := ctx.Err()
		var savedID, saveErr string
		if keep != nil && err == nil && rep != nil && ctxErr == nil {
			if e, serr := keep.Save(rep); serr != nil {
				saveErr = serr.Error()
			} else {
				savedID = e.ID
			}
		}
		s.finish(job, rep, err, ctxErr, savedID, saveErr)
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

func (s *scanJobs) finish(job *scanJob, rep *finding.Report, err, ctxErr error, savedID, saveErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.ended = time.Now()
	job.savedID, job.saveErr = savedID, saveErr
	switch {
	case ctxErr != nil:
		// Une analyse annulee ne rend rien: un resultat partiel passerait pour
		// un depot verifie.
		job.state = stateCanceled
	case err != nil:
		job.state = stateFailed
		job.err = err.Error()
		var coded interface{ Code() string }
		if errors.As(err, &coded) {
			job.errCode = coded.Code()
		}
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

// scanLimits dit ce que l'audit permet, pour que la page l'affiche comme elle
// affiche le quota de recherche: une analyse a la fois, un delai par moteur.
// Le clone passe par git, il ne touche pas au quota de l'API GitHub.
func (s *Server) scanLimits() map[string]any {
	limits := map[string]any{"concurrent": 1}
	if s.ScanTimeout > 0 {
		limits["engine_timeout_s"] = int(s.ScanTimeout.Seconds())
	}
	return limits
}

// maxFormBytes borne le corps des requetes qui lancent ou annulent: une
// reference de depot tient en quelques dizaines d'octets.
const maxFormBytes = 4 << 10

// handleScan lance une analyse (POST) ou rend l'analyse courante (GET).
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		writeJSON(w, http.StatusOK, map[string]any{"available": s.Scan != nil, "job": s.scans.current(), "limits": s.scanLimits()})
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
		target, err := ParseTarget(r.PostForm.Get("cible"))
		// A l'ecoute de tout le reseau, la page peut etre ouverte d'une autre
		// machine: un dossier de celle-ci n'a pas a lui etre lu.
		if err == nil && target.Local() && ListensEverywhere(s.Addr) {
			err = errLocalOff
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "code": targetErrorCode(err)})
			return
		}
		// La case « Enregistrer le rapport » de la page: rien n'est garde sans
		// elle, ou sans le bouton « enregistrer » une fois l'analyse finie.
		var keep *reports.Store
		if r.PostForm.Get("enregistrer") == "1" {
			keep = s.Reports
		}
		job, started, err := s.scans.start(s.Scan, target, keep)
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
// derniere analyse ou d'un rapport enregistre. Il ne fait que lire le rapport.
func (s *Server) handleScanAdvisory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "methode non permise"})
		return
	}
	q := r.URL.Query()
	rep, ok := s.reportFor(q.Get("id"))
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
