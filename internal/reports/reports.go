// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package reports garde les rapports d'analyse sur la machine, pour les
// rouvrir plus tard, sans reseau, et y preparer un signalement.
//
// Un rapport decrit des failles encore non corrigees, parfois le code d'un
// depot prive: il reste dans le dossier de l'utilisateur, lisible par lui
// seul, et ne part nulle part. Le nom de chaque fichier est tire par Quaero au
// moment de l'enregistrer, jamais lu dans le rapport, pour qu'un rapport
// importe ne choisisse ni ou il s'ecrit ni sa place dans la liste.
package reports

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/terrypsv/Quaero/internal/advisory"
	"github.com/terrypsv/Quaero/internal/finding"
)

// MaxBytes borne la taille d'un rapport, importe comme enregistre.
const MaxBytes = 20 << 20

// maxFindings borne le nombre de constats d'un rapport.
const maxFindings = 50000

// maxContextBytes borne le contexte libre d'un rapport importe. Celui d'une
// analyse tient en quelques centaines d'octets, un contexte enorme ne sert
// qu'a faire gonfler la memoire au decodage.
const maxContextBytes = 64 << 10

// Store est le dossier des rapports. Le resume de chaque rapport est garde en
// memoire tant que son fichier ne change pas: la liste ne relit pas tout le
// dossier a chaque affichage.
type Store struct {
	Dir string

	mu    sync.Mutex // garde cache
	cache map[string]cached

	importing sync.Mutex // un import a la fois, pour ne pas ranger deux fois
}

type cached struct {
	size     int64
	mod      time.Time
	entry    Entry
	run      string
	finished time.Time
}

// DefaultDir rend ~/.quaero/rapports, a cote du jeton enregistre.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("repertoire personnel introuvable: %w", err)
	}
	return filepath.Join(home, ".quaero", "rapports"), nil
}

// Entry resume un rapport enregistre, pour la liste.
type Entry struct {
	ID       string    `json:"id"`
	Target   string    `json:"cible"`
	Commit   string    `json:"commit,omitempty"`
	Date     time.Time `json:"date"`
	Findings int       `json:"constats"`
	Seconds  float64   `json:"duree_s"`
}

// idRe est la forme des noms tires par Quaero: date et heure de
// l'enregistrement, puis du hasard.
var idRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{12}$`)

// Erreurs dites a la page.
var (
	ErrNotFound = errors.New("rapport introuvable")
	ErrInvalid  = errors.New("ce fichier n'est pas un rapport Quaero")
	ErrTooBig   = fmt.Errorf("rapport trop gros pour etre garde (plus de %d Mo ou de %d constats)", MaxBytes>>20, maxFindings)
)

// ValidID dit si id est un nom de rapport tire par Quaero. Tout autre nom est
// refuse avant de toucher au disque.
func ValidID(id string) bool { return idRe.MatchString(id) }

func (s *Store) path(id string) string { return filepath.Join(s.Dir, id+".json") }

// Save enregistre rep sous un nom neuf et rend son resume. Un rapport que Load
// ne saurait pas relire n'est pas ecrit.
func (s *Store) Save(rep *finding.Report) (Entry, error) {
	if rep == nil {
		return Entry{}, ErrInvalid
	}
	if len(rep.Findings) > maxFindings {
		return Entry{}, ErrTooBig
	}
	data, err := json.Marshal(rep)
	if err != nil {
		return Entry{}, err
	}
	if len(data) > MaxBytes {
		return Entry{}, ErrTooBig
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Entry{}, err
	}
	// Un dossier cree plus large par un autre outil est resserre. Sous Windows,
	// seul l'attribut lecture seule bouge, les droits restent ceux du profil.
	// #nosec G302 -- c'est un dossier: 0700 est le minimum pour y entrer.
	_ = os.Chmod(s.Dir, 0o700)
	for try := 0; ; try++ {
		id, err := newID(time.Now())
		if err != nil {
			return Entry{}, err
		}
		err = writeNew(s.path(id), data)
		if errors.Is(err, fs.ErrExist) && try < 3 {
			continue
		}
		if err != nil {
			return Entry{}, err
		}
		e := entryOf(id, rep)
		if info, err := os.Stat(s.path(id)); err == nil {
			s.remember(id, info, e, rep)
		}
		return e, nil
	}
}

// writeNew cree path sans jamais ecraser ni suivre un fichier existant. 0600:
// le rapport decrit des failles non corrigees.
func writeNew(path string, data []byte) error {
	// #nosec G304 -- path vient de Store.path, un nom tire par Quaero et
	// verifie par ValidID, jamais lu dans le rapport.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// Import lit un rapport venu d'ailleurs (un fichier -scan-json), le verifie,
// puis l'enregistre comme les autres. Une analyse deja rangee, par exemple un
// fichier repris du dossier des rapports, n'est pas rangee deux fois: Import
// rend alors celle qui y est, et existing le dit.
func (s *Store) Import(data []byte) (e Entry, existing bool, err error) {
	rep, err := Parse(data)
	if err != nil {
		return Entry{}, false, err
	}
	s.importing.Lock()
	defer s.importing.Unlock()
	if e, ok := s.find(rep); ok {
		return e, true, nil
	}
	e, err = s.Save(rep)
	return e, false, err
}

// find cherche la meme analyse parmi les rapports ranges: meme identifiant
// d'execution, meme fin.
func (s *Store) find(rep *finding.Report) (Entry, bool) {
	if rep.Run.ID == "" || rep.Run.FinishedAt.IsZero() {
		return Entry{}, false
	}
	ids, err := s.ids()
	if err != nil {
		return Entry{}, false
	}
	for _, id := range ids {
		c, ok := s.summary(id)
		if ok && c.run == rep.Run.ID && c.finished.Equal(rep.Run.FinishedAt) {
			return c.entry, true
		}
	}
	return Entry{}, false
}

// Parse lit et verifie un rapport. Son contenu reste une donnee: seul le
// schema est controle, rien n'y est execute ni suivi. Les tailles sont
// verifiees avant le decodage complet.
func Parse(data []byte) (*finding.Report, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w (plus de %d Mo)", ErrInvalid, MaxBytes>>20)
	}
	data = bytes.TrimSpace(data)
	var probe struct {
		Run struct {
			Context json.RawMessage `json:"context"`
		} `json:"run"`
		// struct{} ne garde rien: compter les constats ne coute pas leur copie.
		Findings []struct{} `json:"findings"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, ErrInvalid
	}
	if len(probe.Findings) > maxFindings {
		return nil, fmt.Errorf("%w (plus de %d constats)", ErrInvalid, maxFindings)
	}
	if len(probe.Run.Context) > maxContextBytes {
		return nil, fmt.Errorf("%w (contexte de plus de %d Ko)", ErrInvalid, maxContextBytes>>10)
	}
	var rep finding.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, ErrInvalid
	}
	if !strings.HasPrefix(rep.SchemaVersion, "1.") || rep.Tool.Name == "" || rep.Findings == nil {
		return nil, ErrInvalid
	}
	return &rep, nil
}

// Load relit le rapport id.
func (s *Store) Load(id string) (*finding.Report, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, ErrNotFound
	}
	return Parse(data)
}

// Delete efface le rapport id. Un fichier tenu par un autre programme se dit
// tel quel, il n'est pas introuvable.
func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	err := os.Remove(s.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		err = ErrNotFound
	}
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
	return err
}

// List rend les rapports enregistres, de l'analyse la plus recente a la plus
// ancienne. Un fichier illisible est ignore plutot que de cacher les autres.
func (s *Store) List() ([]Entry, error) {
	ids, err := s.ids()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		if c, ok := s.summary(id); ok {
			out = append(out, c.entry)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := sortKey(out[i]), sortKey(out[j])
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// sortKey date un rapport pour la liste: la fin de son analyse, sans depasser
// le moment ou il a ete range. Un rapport importe date du futur ne reste pas
// en tete pour toujours.
func sortKey(e Entry) time.Time {
	saved, err := time.Parse("20060102-150405", e.ID[:15])
	if err != nil || (!e.Date.IsZero() && e.Date.Before(saved)) {
		return e.Date
	}
	return saved
}

// ids rend les noms valides du dossier, du plus recent au plus ancien. Le nom
// commence par la date d'enregistrement, l'ordre des noms est celui du temps.
func (s *Store) ids() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && e.Type().IsRegular() && ValidID(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// summary rend le resume du rapport id, relu seulement si son fichier a change
// depuis la derniere lecture.
func (s *Store) summary(id string) (cached, bool) {
	info, err := os.Stat(s.path(id))
	if err != nil {
		return cached{}, false
	}
	s.mu.Lock()
	c, ok := s.cache[id]
	s.mu.Unlock()
	if ok && c.size == info.Size() && c.mod.Equal(info.ModTime()) {
		return c, true
	}
	rep, err := s.Load(id)
	if err != nil {
		return cached{}, false
	}
	return s.remember(id, info, entryOf(id, rep), rep), true
}

func (s *Store) remember(id string, info fs.FileInfo, e Entry, rep *finding.Report) cached {
	c := cached{size: info.Size(), mod: info.ModTime(), entry: e, run: rep.Run.ID, finished: rep.Run.FinishedAt}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]cached{}
	}
	s.cache[id] = c
	s.mu.Unlock()
	return c
}

func entryOf(id string, rep *finding.Report) Entry {
	e := Entry{ID: id, Findings: shownCount(advisory.Candidates(rep))}
	e.Target, _ = rep.Run.Context["cible"].(string)
	if e.Target == "" {
		e.Target, _ = rep.Run.Context["path"].(string)
	}
	e.Commit, _ = rep.Run.Context["commit"].(string)
	e.Date = rep.Run.FinishedAt
	if e.Date.IsZero() {
		e.Date = rep.Run.StartedAt
	}
	if !rep.Run.FinishedAt.IsZero() && !rep.Run.StartedAt.IsZero() {
		e.Seconds = math.Round(rep.Run.FinishedAt.Sub(rep.Run.StartedAt).Seconds()*10) / 10
	}
	return e
}

// shownCount compte ce que la page montre: un element par constat de code, un
// par dependance avec toutes ses vulnerabilites publiees (voir auditItems dans
// internal/webui/index.html), pour que la liste et le rapport ouvert disent le
// meme nombre.
func shownCount(list []finding.Finding) int {
	deps := map[string]bool{}
	n := 0
	for _, f := range list {
		if !published(f) {
			n++
			continue
		}
		name := "?"
		if f.Target != nil && f.Target.Identifier != "" {
			name = f.Target.Identifier
			if at := strings.LastIndex(name, "@"); at > 0 {
				name = name[:at]
			}
		}
		if !deps[name] {
			deps[name] = true
			n++
		}
	}
	return n
}

// published reconnait une vulnerabilite publiee d'une dependance, comme
// isPublished dans la page.
func published(f finding.Finding) bool {
	if f.Target != nil && f.Target.Type == "dependency" {
		return true
	}
	for _, r := range f.References {
		if r.Framework == "OSV" || r.Framework == "GHSA" || r.Framework == "CVE" {
			return true
		}
	}
	return false
}

// newID tire un nom: la date d'enregistrement, en UTC, puis du hasard.
func newID(when time.Time) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return when.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b), nil
}
