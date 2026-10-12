// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/terrypsv/Quaero/internal/model"
)

// reader tracks, while a phrase is being read, which part of it produced what.
//
// The reading works on a lowercased, accent-free copy of the phrase. That copy
// keeps one rune per rune of the original, so a position in it is also a
// position in what was typed, and every recognised piece can be shown back
// with the user's own spelling. What has been consumed is blanked with as many
// spaces as it had bytes, never shortened, so positions stay valid until the
// end.
type reader struct {
	phrase string // as typed
	norm   string // normalised, same rune count as phrase
	rest   string // norm with every consumed piece blanked
	spans  []span
}

type span struct {
	start, end int // byte offsets in norm
	role       string
	value      string
}

func newReader(phrase string) *reader {
	norm := normalise(phrase)
	return &reader{phrase: phrase, norm: norm, rest: norm}
}

// isWordRune matches the characters words are made of, the same set the term
// splitter keeps, so that "c++", "node.js" or "base64" stay whole.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune("+#._-", r)
}

// find returns the first occurrence of piece in what is left that starts a
// word, extended to the end of that word. "maintenu" is found in
// "maintenues", which leaves no "es" behind to be searched for, but not in
// "inactif" for "actif": an inflection follows a word, it does not precede it.
func (rd *reader) find(piece string) (int, int, bool) {
	from := 0
	for {
		i := strings.Index(rd.rest[from:], piece)
		if i < 0 {
			return 0, 0, false
		}
		start := from + i
		if prev, _ := utf8.DecodeLastRuneInString(rd.rest[:start]); start == 0 || !isWordRune(prev) {
			return start, rd.wordEnd(start + len(piece)), true
		}
		from = start + 1
	}
}

// wordEnd moves end forward to the end of the word it falls in.
func (rd *reader) wordEnd(end int) int {
	for end < len(rd.rest) {
		r, size := utf8.DecodeRuneInString(rd.rest[end:])
		if !isWordRune(r) {
			break
		}
		end += size
	}
	return end
}

// startsWord reports whether a match at start begins a word.
func (rd *reader) startsWord(start int) bool {
	prev, _ := utf8.DecodeLastRuneInString(rd.rest[:start])
	return start == 0 || !isWordRune(prev)
}

// take records a piece and blanks it so that nothing reads it twice.
func (rd *reader) take(start, end int, role, value string) {
	rd.spans = append(rd.spans, span{start: start, end: end, role: role, value: value})
	rd.rest = rd.rest[:start] + strings.Repeat(" ", end-start) + rd.rest[end:]
}

// relabel changes the role of the term spans whose value is not kept.
func (rd *reader) relabel(kept map[string]bool) {
	for i := range rd.spans {
		if rd.spans[i].role == model.RoleTerm && !kept[rd.spans[i].value] {
			rd.spans[i].role = model.RoleOverLimits
		}
	}
}

// segments cuts the phrase as typed along the recorded pieces. The text
// between two pieces is kept as a separator, so that joining every segment
// gives the phrase back. When the normalised copy does not line up rune for
// rune with the phrase, nothing is returned rather than a misaligned reading.
func (rd *reader) segments() []model.Segment {
	orig := []rune(rd.phrase)
	if len(orig) != utf8.RuneCountInString(rd.norm) {
		return nil
	}
	// runeAt converts a byte offset in norm into a rune index, which is also
	// a rune index in the phrase. Pieces always start and end on a rune.
	runeAt := make([]int, len(rd.norm)+1)
	n := 0
	for i := range rd.norm {
		runeAt[i] = n
		n++
	}
	runeAt[len(rd.norm)] = n

	spans := append([]span(nil), rd.spans...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var out []model.Segment
	cursor := 0
	for _, sp := range spans {
		a, b := runeAt[sp.start], runeAt[sp.end]
		if a > cursor {
			out = append(out, model.Segment{Text: string(orig[cursor:a])})
		}
		out = append(out, model.Segment{Text: string(orig[a:b]), Role: sp.role, Value: sp.value})
		cursor = b
	}
	if cursor < len(orig) {
		out = append(out, model.Segment{Text: string(orig[cursor:])})
	}
	return out
}
