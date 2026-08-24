// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package rank

import (
	"strings"
	"unicode"

	"github.com/terrypsv/Quaero/internal/model"
)

// Writing systems a description can be in. These are scripts, not countries
// and not languages, and the distinction is deliberate.
//
// GitHub does not record where a repository comes from. The `location:`
// qualifier exists but applies to user search, not repository search, so a
// country filter would have to be invented from data that does not exist.
// Detecting the script of a description is something that can actually be
// done from what the API returns, and it answers most of the same question:
// it separates the Chinese-speaking, Russian-speaking and Arabic-speaking
// bodies of work from the Latin-alphabet default.
//
// The limits are worth stating. Latin covers French, English, Spanish, German
// and Vietnamese alike, so it separates nothing within that group. And a
// repository with an English description written by a Japanese team reads as
// Latin, because that is what the description is.
const (
	ScriptLatin      = "latin"
	ScriptHan        = "chinois"
	ScriptJapanese   = "japonais"
	ScriptKorean     = "coreen"
	ScriptCyrillic   = "cyrillique"
	ScriptArabic     = "arabe"
	ScriptHebrew     = "hebreu"
	ScriptGreek      = "grec"
	ScriptDevanagari = "devanagari"
	ScriptThai       = "thai"
	ScriptUnknown    = "indetermine"
)

// DetectScript reports the dominant writing system of a description.
//
// Dominance rather than presence: a mostly-English description containing one
// Chinese character is English, and calling it Chinese would put it in a
// filter where nobody expects to find it. Japanese is checked before Han
// because Japanese text mixes kana with Chinese characters, and the kana are
// what makes it Japanese.
func DetectScript(text string) string {
	if strings.TrimSpace(text) == "" {
		return ScriptUnknown
	}

	counts := map[string]int{}
	letters := 0

	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		switch {
		case unicode.In(r, unicode.Hiragana, unicode.Katakana):
			counts[ScriptJapanese]++
		case unicode.In(r, unicode.Hangul):
			counts[ScriptKorean]++
		case unicode.In(r, unicode.Han):
			counts[ScriptHan]++
		case unicode.In(r, unicode.Cyrillic):
			counts[ScriptCyrillic]++
		case unicode.In(r, unicode.Arabic):
			counts[ScriptArabic]++
		case unicode.In(r, unicode.Hebrew):
			counts[ScriptHebrew]++
		case unicode.In(r, unicode.Greek):
			counts[ScriptGreek]++
		case unicode.In(r, unicode.Devanagari):
			counts[ScriptDevanagari]++
		case unicode.In(r, unicode.Thai):
			counts[ScriptThai]++
		case unicode.In(r, unicode.Latin):
			counts[ScriptLatin]++
		}
	}

	if letters == 0 {
		return ScriptUnknown
	}

	// Kana are sparse in Japanese text but decisive: a handful among Han
	// characters means the text is Japanese, not Chinese.
	if counts[ScriptJapanese] > 0 && counts[ScriptHan] > 0 {
		counts[ScriptJapanese] += counts[ScriptHan]
		delete(counts, ScriptHan)
	}

	best, bestCount := ScriptUnknown, 0
	for script, n := range counts {
		if n > bestCount {
			best, bestCount = script, n
		}
	}

	// A non-Latin script only needs a minority to be the real language of the
	// text, because Latin characters leak into every description through
	// project names, versions and URLs.
	if best == ScriptLatin {
		for script, n := range counts {
			if script != ScriptLatin && n*4 >= letters {
				return script
			}
		}
	}
	return best
}

// TagScripts fills the Script field of every repository.
func TagScripts(repos []model.Repo) {
	for i := range repos {
		repos[i].Script = DetectScript(repos[i].Description)
	}
}
