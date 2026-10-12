// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"strings"
	"unicode/utf8"

	"github.com/terrypsv/Quaero/internal/model"
)

// exclusionMarkers introduce a word to keep out of the results: "un scanner
// de ports, pas de nmap", "pot de miel sauf cowrie". A word typed with a
// leading minus ("-nmap") does the same, and is handled with the other words.
//
// "sans" is deliberately not a marker. "sans agent", "sans dependances" or
// "sans root" describe a feature (agentless, zero-dependency, rootless), not
// something to exclude, and reading them as exclusions would throw away the
// very projects asked for. "not" is left out for the same reason: "not
// maintained" is a description, not a ban on a word.
var exclusionMarkers = []string{"pas de", "pas d'", "pas d ", "sauf", "hors", "excepte", "except", "excluding"}

// articles may sit between a marker and the word it excludes.
var articles = map[string]bool{
	"le": true, "la": true, "les": true, "l": true, "de": true, "du": true,
	"des": true, "d": true, "un": true, "une": true, "the": true, "a": true,
}

// maxExclusions bounds the NOT operators a phrase can produce. GitHub refuses
// a query with more than five, and one is kept for the lists filter.
const maxExclusions = 4

// licenseKeys maps what people type after "licence" to GitHub's license
// keys. Only the families people actually ask for are listed; an unknown name
// is left to be read as an ordinary word.
var licenseKeys = map[string]string{
	"mit":    "mit",
	"apache": "apache-2.0", "apache2": "apache-2.0", "apache-2": "apache-2.0", "apache-2.0": "apache-2.0",
	"gpl": "gpl-3.0", "gplv3": "gpl-3.0", "gpl3": "gpl-3.0", "gpl-3.0": "gpl-3.0",
	"gplv2": "gpl-2.0", "gpl2": "gpl-2.0", "gpl-2.0": "gpl-2.0",
	"agpl": "agpl-3.0", "agplv3": "agpl-3.0", "agpl-3.0": "agpl-3.0",
	"lgpl": "lgpl-3.0", "lgplv3": "lgpl-3.0", "lgpl-3.0": "lgpl-3.0",
	"bsd": "bsd-3-clause", "bsd-3-clause": "bsd-3-clause", "bsd-2-clause": "bsd-2-clause",
	"mpl": "mpl-2.0", "mpl-2.0": "mpl-2.0",
	"isc":       "isc",
	"unlicense": "unlicense",
}

// findWhole returns the first occurrence of piece in what is left that is a
// whole word: it starts a word and, unless it ends on a separator, is not
// followed by more of the same word. "hors" is found in "hors windows", not
// in "horsepower".
func (rd *reader) findWhole(piece string) (int, int, bool) {
	from := 0
	for {
		i := strings.Index(rd.rest[from:], piece)
		if i < 0 {
			return 0, 0, false
		}
		start := from + i
		end := start + len(piece)
		last := piece[len(piece)-1]
		if rd.startsWord(start) && (last == '\'' || last == ' ' || end == len(rd.rest) || !rd.wordRuneAt(end)) {
			return start, end, true
		}
		from = start + 1
	}
}

func (rd *reader) wordRuneAt(i int) bool {
	r, _ := utf8.DecodeRuneInString(rd.rest[i:])
	return isWordRune(r)
}

// wordAt returns the end of the word starting exactly at pos, or pos when
// there is none.
func (rd *reader) wordAt(pos int) int {
	end := pos
	for end < len(rd.rest) && rd.wordRuneAt(end) {
		_, size := utf8.DecodeRuneInString(rd.rest[end:])
		end += size
	}
	return end
}

// skipFiller moves past spaces, apostrophes and articles.
func (rd *reader) skipFiller(pos int) int {
	for pos < len(rd.rest) {
		switch rd.rest[pos] {
		case ' ', '\'', ',':
			pos++
			continue
		}
		end := rd.wordAt(pos)
		if end > pos && articles[rd.rest[pos:end]] {
			pos = end
			continue
		}
		break
	}
	return pos
}

// excludedAt reads what a marker excludes, starting at pos: a known
// expression first ("sauf active directory" excludes the product, not the
// word "active"), otherwise one word, translated like any other.
func (rd *reader) excludedAt(pos int) (term string, end int) {
	for _, m := range multiWord {
		if strings.HasPrefix(rd.rest[pos:], m.phrase) {
			e := pos + len(m.phrase)
			if e == len(rd.rest) || !rd.wordRuneAt(e) {
				return m.term, e
			}
		}
	}
	end = rd.wordAt(pos)
	word := strings.TrimLeft(rd.rest[pos:end], "-")
	if len(word) < 2 || stopWords[word] {
		return "", pos
	}
	return translate(word), end
}

// readExclusions takes every marker and what follows it, before anything
// else reads the phrase.
func readExclusions(rd *reader, out *model.Intent) {
	for _, marker := range exclusionMarkers {
		for {
			start, end, ok := rd.findWhole(marker)
			if !ok {
				break
			}
			pos := rd.skipFiller(end)
			term, termEnd := rd.excludedAt(pos)
			if term == "" {
				// A marker with nothing to exclude behind it is just a word.
				rd.take(start, end, model.RoleEmpty, "")
				continue
			}
			rd.take(start, pos, model.RoleEmpty, "")
			addExclusion(rd, out, pos, termEnd, term)
		}
	}
}

// addExclusion records one excluded term, within the operator budget.
func addExclusion(rd *reader, out *model.Intent, start, end int, term string) {
	for _, x := range out.Exclude {
		if x == term {
			rd.take(start, end, model.RoleExcluded, term)
			return
		}
	}
	if len(out.Exclude) >= maxExclusions {
		rd.take(start, end, model.RoleOverLimits, term)
		return
	}
	out.Exclude = append(out.Exclude, term)
	out.Explain = append(out.Explain, "exclu: "+term)
	rd.take(start, end, model.RoleExcluded, term)
}

// readLicense takes "licence mit", "license apache" and the like.
func readLicense(rd *reader, out *model.Intent) {
	for _, marker := range []string{"licence", "license"} {
		start, end, ok := rd.findWhole(marker)
		if !ok {
			continue
		}
		pos := rd.skipFiller(end)
		wordEnd := rd.wordAt(pos)
		key, known := licenseKeys[rd.rest[pos:wordEnd]]
		if !known {
			continue
		}
		out.License = key
		out.Explain = append(out.Explain, "licence: "+key)
		rd.take(start, wordEnd, model.RoleLicense, key)
		return
	}
}
