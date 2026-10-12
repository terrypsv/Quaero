// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package rank

import (
	"strings"
	"unicode"
)

// Languages a description can be detected in. The script answers most of the
// question for the non-Latin alphabets; within the Latin one, the small words
// every sentence needs ("the", "pour", "und") tell English from French or
// German far better than the technical vocabulary, which is English in every
// language.
const (
	LangEnglish    = "anglais"
	LangFrench     = "francais"
	LangSpanish    = "espagnol"
	LangPortuguese = "portugais"
	LangGerman     = "allemand"
	LangItalian    = "italien"
	LangVietnamese = "vietnamien"
	LangRussian    = "russe"
	LangUkrainian  = "ukrainien"
	LangChinese    = "chinois"
	LangJapanese   = "japonais"
	LangKorean     = "coreen"
	LangArabic     = "arabe"
	LangHebrew     = "hebreu"
	LangGreek      = "grec"
	LangHindi      = "hindi"
	LangThai       = "thai"
	LangOther      = "autre"
)

// functionWords are the short words that carry no meaning of their own and
// therefore appear in almost every sentence of a language. A word shared by
// several languages ("de", "la") counts for each of them; the words that are
// not shared decide.
var functionWords = map[string][]string{
	LangEnglish: {"the", "and", "for", "with", "of", "to", "in", "on", "is", "are", "this", "that",
		"your", "you", "from", "by", "an", "it", "its", "as", "be", "can", "which", "using", "into",
		"written", "based", "made", "all", "any", "without", "over", "will", "has", "have"},
	LangFrench: {"le", "la", "les", "des", "du", "de", "un", "une", "et", "pour", "avec", "dans", "sur",
		"est", "qui", "que", "ce", "cette", "en", "au", "aux", "par", "pas", "ou", "son", "ses", "sont",
		"d", "l", "qu", "outil", "permet", "permettant", "votre", "vos"},
	LangSpanish: {"el", "los", "las", "del", "y", "para", "con", "una", "uno", "por", "que", "es", "en",
		"se", "su", "sus", "como", "de", "la", "herramienta", "permite"},
	LangPortuguese: {"o", "os", "as", "do", "da", "dos", "das", "e", "para", "com", "uma", "um", "por",
		"que", "em", "no", "na", "nao", "de", "ferramenta", "permite"},
	LangGerman: {"der", "die", "das", "und", "fur", "mit", "ein", "eine", "ist", "von", "zu", "den",
		"dem", "nicht", "auf", "auch", "werkzeug", "fuer"},
	LangItalian: {"il", "lo", "gli", "della", "delle", "di", "e", "per", "con", "una", "un", "che",
		"del", "non", "strumento", "la", "le"},
}

// wordLangs inverts functionWords for lookup.
var wordLangs = func() map[string][]string {
	m := map[string][]string{}
	for lang, words := range functionWords {
		for _, w := range words {
			m[w] = append(m[w], lang)
		}
	}
	return m
}()

// letterHints are letters one language uses and the others mostly do not.
// They decide when the small words are missing or tied.
var letterHints = map[rune]string{
	'ç': LangFrench, 'è': LangFrench, 'ê': LangFrench, 'à': LangFrench, 'œ': LangFrench, 'ù': LangFrench, 'î': LangFrench, 'û': LangFrench,
	'ñ': LangSpanish, '¿': LangSpanish, '¡': LangSpanish,
	'ã': LangPortuguese, 'õ': LangPortuguese,
	'ß': LangGerman, 'ä': LangGerman, 'ö': LangGerman, 'ü': LangGerman,
	'ì': LangItalian, 'ò': LangItalian,
}

// vietnameseLetters only occur in Vietnamese among the Latin languages.
const vietnameseLetters = "ăơưđạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ"

// DetectLanguage reports the language a description is written in, or ""
// when there is no description.
//
// A Latin description with no telling word at all ("SSH honeypot", "Port
// scanner") is reported as English: technical names are English whatever the
// author's language, and it is what such a description reads as.
func DetectLanguage(text string) string {
	switch DetectScript(text) {
	case ScriptUnknown:
		if strings.TrimSpace(text) == "" {
			return ""
		}
		return LangOther
	case ScriptHan:
		return LangChinese
	case ScriptJapanese:
		return LangJapanese
	case ScriptKorean:
		return LangKorean
	case ScriptCyrillic:
		// Quatre lettres n'existent qu'en ukrainien.
		if strings.ContainsAny(strings.ToLower(text), "іїєґ") {
			return LangUkrainian
		}
		return LangRussian
	case ScriptArabic:
		return LangArabic
	case ScriptHebrew:
		return LangHebrew
	case ScriptGreek:
		return LangGreek
	case ScriptDevanagari:
		return LangHindi
	case ScriptThai:
		return LangThai
	}
	return detectLatin(text)
}

func detectLatin(text string) string {
	lower := strings.ToLower(text)
	if strings.ContainsAny(lower, vietnameseLetters) {
		return LangVietnamese
	}

	score := map[string]float64{}
	for _, r := range lower {
		if lang, ok := letterHints[r]; ok {
			score[lang] += 0.5
		}
	}
	words := strings.FieldsFunc(stripAccents(lower), func(r rune) bool { return !unicode.IsLetter(r) })
	for _, w := range words {
		langs := wordLangs[w]
		for _, lang := range langs {
			// Un mot propre a une langue pese plus qu'un mot partage.
			score[lang] += 1 / float64(len(langs))
		}
	}

	best, bestScore := LangEnglish, 0.0
	for _, lang := range []string{LangEnglish, LangFrench, LangSpanish, LangPortuguese, LangGerman, LangItalian} {
		if score[lang] > bestScore {
			best, bestScore = lang, score[lang]
		}
	}
	return best
}

// stripAccents folds the accented letters the function words carry, so that
// "für", "não" and "è" match their listed forms.
func stripAccents(s string) string {
	return strings.NewReplacer(
		"á", "a", "à", "a", "â", "a", "ä", "a", "ã", "a",
		"é", "e", "è", "e", "ê", "e", "ë", "e",
		"í", "i", "ì", "i", "î", "i", "ï", "i",
		"ó", "o", "ò", "o", "ô", "o", "ö", "o", "õ", "o",
		"ú", "u", "ù", "u", "û", "u", "ü", "u",
		"ç", "c", "ñ", "n",
	).Replace(s)
}
