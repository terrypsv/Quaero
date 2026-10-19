// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package triage garde les decisions de tri prises sur les constats: a
// verifier, faux positif, confirme, signale. Elles valent pour un depot et
// survivent aux analyses suivantes, tant que le code signale ne change pas.
//
// Une decision est rattachee a l'empreinte du constat, pas a son identifiant:
// l'identifiant porte le numero de ligne, qui bouge des qu'on ajoute une ligne
// plus haut. L'empreinte tient a la regle, au fichier et au texte de la ligne
// signalee. Si ce texte change, la decision ne s'applique plus et le constat
// redevient a verifier, ce qui est voulu: le code a change, il se relit.
//
// Tout reste sur la machine, dans le dossier de l'utilisateur.
package triage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/terrypsv/Quaero/internal/finding"
)

// State est une decision de tri.
type State string

// Decisions possibles. ToReview est l'etat par defaut et n'est pas ecrit.
const (
	ToReview      State = "a_verifier"
	FalsePositive State = "faux_positif"
	Confirmed     State = "confirme"
	Reported      State = "signale"
)

// ParseState lit une decision venue de la page.
func ParseState(s string) (State, bool) {
	switch st := State(s); st {
	case ToReview, FalsePositive, Confirmed, Reported:
		return st, true
	}
	return "", false
}

// Decision est ce que l'utilisateur a decide d'un constat.
type Decision struct {
	State State     `json:"etat"`
	Note  string    `json:"note,omitempty"`
	Date  time.Time `json:"date"`
}

// MaxNote borne la note jointe a une decision, en caracteres.
const MaxNote = 500

// maxEntries borne le nombre de decisions gardees, tous depots confondus.
const maxEntries = 50000

// maxFileBytes borne la taille du fichier relu.
var maxFileBytes = 16 << 20

// Erreurs dites a la page.
var (
	ErrUnknownFinding = errors.New("constat introuvable dans ce rapport")
	ErrNoTarget       = errors.New("rapport sans cible, rien a quoi rattacher la decision")
	ErrFull           = fmt.Errorf("plus de %d decisions de tri gardees, rien n'est ajoute", maxEntries)
	ErrTooBig         = fmt.Errorf("le fichier de tri depasserait %d Mo, rien n'est ajoute", maxFileBytes>>20)
)

// Store est le fichier des decisions. Il est relu des qu'il a change sur le
// disque, pour qu'un second Quaero ouvert en meme temps n'efface pas ce que
// le premier a ecrit.
type Store struct {
	Path string

	mu     sync.Mutex
	loaded bool
	data   fileData
	stamp  fileStamp
}

type fileData struct {
	Version int                            `json:"version"`
	Targets map[string]map[string]Decision `json:"cibles"`
}

// fileStamp reconnait un fichier qui a change depuis la derniere lecture.
type fileStamp struct {
	size int64
	mod  time.Time
}

// DefaultPath rend ~/.quaero/tri.json, a cote des rapports.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("repertoire personnel introuvable: %w", err)
	}
	return filepath.Join(home, ".quaero", "tri.json"), nil
}

// For rend les decisions qui s'appliquent aux constats de rep, par
// identifiant de constat. Les constats a verifier n'y figurent pas.
func (s *Store) For(rep *finding.Report) map[string]Decision {
	out := map[string]Decision{}
	if rep == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refresh() != nil {
		return out
	}
	key := TargetKey(rep)
	byFP := s.data.Targets[key]
	if key == "" || len(byFP) == 0 {
		return out
	}
	for id, fp := range Fingerprints(rep) {
		if d, ok := byFP[fp]; ok {
			out[id] = d
		}
	}
	return out
}

// Set enregistre la decision prise sur le constat id de rep. ToReview efface
// la decision. Le fichier est reecrit en entier, dans un fichier temporaire
// puis renomme: une coupure en route laisse l'ancien intact. Si l'ecriture
// echoue, la memoire n'est pas changee non plus.
func (s *Store) Set(rep *finding.Report, id string, st State, note string) (Decision, error) {
	if rep == nil || strings.HasPrefix(id, "QRO-SCAN-") {
		return Decision{}, ErrUnknownFinding
	}
	fp, ok := Fingerprints(rep)[id]
	if !ok {
		return Decision{}, ErrUnknownFinding
	}
	key := TargetKey(rep)
	if key == "" {
		return Decision{}, ErrNoTarget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return Decision{}, err
	}

	next := make(map[string]Decision, len(s.data.Targets[key])+1)
	for k, v := range s.data.Targets[key] {
		next[k] = v
	}
	d := Decision{State: st, Note: cleanNote(note), Date: time.Now().UTC()}
	if st == ToReview {
		delete(next, fp)
		d = Decision{State: ToReview}
	} else {
		if _, exists := next[fp]; !exists && s.count() >= maxEntries {
			return Decision{}, ErrFull
		}
		next[fp] = d
	}
	data := fileData{Version: 1, Targets: make(map[string]map[string]Decision, len(s.data.Targets)+1)}
	for k, v := range s.data.Targets {
		data.Targets[k] = v
	}
	if len(next) == 0 {
		delete(data.Targets, key)
	} else {
		data.Targets[key] = next
	}
	if err := s.save(data); err != nil {
		return Decision{}, err
	}
	s.data = data
	return d, nil
}

func (s *Store) count() int {
	n := 0
	for _, m := range s.data.Targets {
		n += len(m)
	}
	return n
}

// refresh relit le fichier s'il a change depuis la derniere lecture. Un
// fichier illisible n'est jamais ecrase: l'erreur est rendue a chaque appel,
// le fichier reste a sa place.
func (s *Store) refresh() error {
	info, err := os.Stat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = fileData{Version: 1, Targets: map[string]map[string]Decision{}}
		s.stamp, s.loaded = fileStamp{}, true
		return nil
	}
	if err != nil {
		return fmt.Errorf("fichier de tri illisible: %w", err)
	}
	stamp := fileStamp{size: info.Size(), mod: info.ModTime()}
	if s.loaded && stamp == s.stamp {
		return nil
	}
	s.loaded = false
	if info.Size() > int64(maxFileBytes) {
		return fmt.Errorf("fichier de tri illisible (%s), plus de %d Mo", s.Path, maxFileBytes>>20)
	}
	// #nosec G304 -- chemin fixe sous le dossier utilisateur (DefaultPath).
	raw, err := os.ReadFile(s.Path)
	var data fileData
	if err == nil {
		err = json.Unmarshal(raw, &data)
	}
	if err != nil {
		return fmt.Errorf("fichier de tri illisible (%s), a corriger ou a deplacer: %w", s.Path, err)
	}
	if data.Targets == nil {
		data.Targets = map[string]map[string]Decision{}
	}
	s.data, s.stamp, s.loaded = data, stamp, true
	return nil
}

// save ecrit data a la place du fichier, sans jamais laisser un fichier que
// refresh refuserait de relire.
func (s *Store) save(data fileData) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Sans echappement HTML, « < » reste un octet: la taille ecrite est celle
	// que l'on compte.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return err
	}
	if buf.Len() > maxFileBytes {
		return ErrTooBig
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// 0600 (CreateTemp): les notes peuvent decrire une faille non corrigee.
	tmp, err := os.CreateTemp(dir, "tri-*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(buf.Bytes())
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.Path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if info, err := os.Stat(s.Path); err == nil {
		s.stamp, s.loaded = fileStamp{size: info.Size(), mod: info.ModTime()}, true
	} else {
		s.loaded = false
	}
	return nil
}

func cleanNote(n string) string {
	n = strings.Join(strings.Fields(n), " ")
	if utf8.RuneCountInString(n) > MaxNote {
		n = string([]rune(n)[:MaxNote])
	}
	return n
}

// TargetKey rend la cle du depot d'un rapport: la cible github.com en
// minuscules, ou le chemin du dossier, sans distinction de casse sous Windows.
func TargetKey(rep *finding.Report) string {
	label, _ := rep.Run.Context["cible"].(string)
	if label == "" {
		label, _ = rep.Run.Context["path"].(string)
	}
	if strings.HasPrefix(strings.ToLower(label), "github.com/") {
		return strings.ToLower(strings.TrimSuffix(label, "/"))
	}
	if label == "" {
		return ""
	}
	// Le meme dossier, nomme par un lien ou par son vrai chemin, est le meme
	// depot. Un dossier absent (rapport d'une autre machine) garde son nom.
	if real, err := filepath.EvalSymlinks(label); err == nil {
		label = real
	}
	label = filepath.Clean(label)
	if runtime.GOOS == "windows" {
		label = strings.ToLower(label)
	}
	return label
}

// Fingerprints rend l'empreinte stable de chaque constat de rep, par
// identifiant. Pour une vulnerabilite publiee: le paquet et l'identifiant
// public. Pour un constat de code: la regle, le titre affiche, le fichier et
// le texte de la ligne signalee, sans son numero. Deux constats qui partagent
// tout cela, deux lignes identiques du meme fichier, sont departages par leur
// rang dans l'ordre des lignes: une decision sur l'un ne vaut pas pour l'autre.
func Fingerprints(rep *finding.Report) map[string]string {
	type item struct {
		id, base string
		line     int
	}
	var items []item
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, "QRO-SCAN-") {
			continue
		}
		base, line := baseKey(f)
		items = append(items, item{f.ID, base, line})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.base != b.base {
			return a.base < b.base
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.id < b.id
	})
	out := make(map[string]string, len(items))
	rank := map[string]int{}
	for _, it := range items {
		rank[it.base]++
		sum := sha256.Sum256([]byte(it.base + "\x00" + strconv.Itoa(rank[it.base])))
		out[it.id] = hex.EncodeToString(sum[:])[:24]
	}
	return out
}

func baseKey(f finding.Finding) (string, int) {
	if name, id := publishedKey(f); id != "" {
		return "dep\x00" + name + "\x00" + id, 0
	}
	p, line := location(f)
	code := codeText(f, line)
	if code == "" {
		code = "ligne " + strconv.Itoa(line)
	}
	return "code\x00" + rule(f) + "\x00" + f.Title + "\x00" + p + "\x00" + code, line
}

func publishedKey(f finding.Finding) (string, string) {
	var osv, ghsa, cve string
	for _, r := range f.References {
		switch {
		case r.Framework == "OSV" && osv == "":
			osv = r.ID
		case r.Framework == "GHSA" && ghsa == "":
			ghsa = r.ID
		case r.Framework == "CVE" && cve == "":
			cve = r.ID
		}
	}
	id := osv
	if id == "" {
		id = ghsa
	}
	if id == "" {
		id = cve
	}
	if id == "" && (f.Target == nil || f.Target.Type != "dependency") {
		return "", ""
	}
	if id == "" {
		id = f.ID
	}
	name := ""
	if f.Target != nil {
		name = f.Target.Identifier
		if at := strings.LastIndex(name, "@"); at > 0 {
			name = name[:at]
		}
	}
	return name, id
}

// Place rend l'endroit d'un constat de code, son fichier et le texte de sa
// ligne, sans la regle ni le numero de ligne: deux analyses qui relevent la
// meme ligne par des regles differentes parlent du meme endroit. Il rend ""
// pour une dependance, ou sans texte de ligne.
func Place(f finding.Finding) string {
	if _, id := publishedKey(f); id != "" {
		return ""
	}
	p, line := location(f)
	code := codeText(f, line)
	if code == "" {
		return ""
	}
	return p + "\x00" + code
}

// location rend le fichier et la ligne d'un constat de code.
func location(f finding.Finding) (string, int) {
	if f.Target == nil {
		return "", 0
	}
	id := f.Target.Identifier
	line := 0
	if m := lineSuffix.FindStringSubmatch(id); m != nil {
		line, _ = strconv.Atoi(m[1])
		id = id[:len(id)-len(m[0])]
	}
	return path.Clean(filepath.ToSlash(id)), line
}

// lineSuffix est le numero de ligne, ou la plage (gosec, « :12-14 »), qui suit
// le fichier dans la cible d'un constat de code. La premiere ligne compte.
var lineSuffix = regexp.MustCompile(`:(\d+)(?:-\d+)?$`)

var numbered = regexp.MustCompile(`^(\d+): ?(.*)$`)

// codeText rend le texte signale, sans numeros ni espaces superflus. gosec
// rend la ligne entouree de ses voisines, numerotees: seule la ligne du
// constat compte, pour qu'un changement juste a cote ne fasse pas oublier la
// decision.
func codeText(f finding.Finding, line int) string {
	var raw string
	for _, e := range f.Evidence {
		if e.Type == "code" {
			raw = e.Data
			break
		}
	}
	if t := strings.TrimSpace(raw); t == "" || strings.EqualFold(t, "requires login") {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	allNumbered, picked := true, ""
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := numbered.FindStringSubmatch(l)
		if m == nil {
			allNumbered = false
			break
		}
		if n, _ := strconv.Atoi(m[1]); n == line {
			picked = m[2]
		}
	}
	if allNumbered && picked != "" {
		return strings.Join(strings.Fields(picked), " ")
	}
	return strings.Join(strings.Fields(raw), " ")
}

// rule rend la regle qui a produit un constat de code: l'identifiant complet
// de la regle semgrep, le code gosec, ou a defaut le titre.
func rule(f finding.Finding) string {
	for _, e := range f.Evidence {
		if e.Type == "rule" && e.Data != "" {
			return e.Data
		}
	}
	if rest, ok := strings.CutPrefix(f.ID, "QRO-GOSEC-"); ok {
		if i := strings.Index(rest, "-"); i > 0 {
			return "gosec:" + rest[:i]
		}
	}
	return f.Title
}
