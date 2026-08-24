// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package intent turns a typed phrase into search facets.
//
// This package is the reason Quaero exists. GitHub's search expects a query
// language: qualifiers, colons, comparison operators. Someone who knows that
// language can find anything; someone who does not gets keyword matching on a
// README and a wall of forks. The gap is not in the index, it is in the
// interface.
//
// So the phrase is read here, not typed as syntax. "une bibliotheque go pour
// parser du yaml, maintenue" becomes terms plus a language facet plus a
// recency facet, and every facet that was understood is reported back. That
// last part matters: a reader who cannot see how their sentence was
// interpreted cannot tell a bad result from a misread question.
package intent

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/terrypsv/Quaero/internal/model"
)

// languages maps the words people actually type to GitHub's language names.
// The keys are lowercase and accent-free; the caller normalises before lookup.
var languages = map[string]string{
	"go": "Go", "golang": "Go",
	"rust":   "Rust",
	"python": "Python", "py": "Python",
	"javascript": "JavaScript", "js": "JavaScript",
	"typescript": "TypeScript", "ts": "TypeScript",
	"java":   "Java",
	"c":      "C",
	"c++":    "C++",
	"cpp":    "C++",
	"c#":     "C#",
	"csharp": "C#",
	"php":    "PHP",
	"ruby":   "Ruby",
	"shell":  "Shell", "bash": "Shell",
	"powershell": "PowerShell",
	"kotlin":     "Kotlin",
	"swift":      "Swift",
	"scala":      "Scala",
	"elixir":     "Elixir",
	"haskell":    "Haskell",
	"lua":        "Lua",
	"zig":        "Zig",
	"perl":       "Perl",
	"r":          "R",
	"dart":       "Dart",
	"nim":        "Nim",
	"ocaml":      "OCaml",
	"clojure":    "Clojure",
	"erlang":     "Erlang",
	"julia":      "Julia",
	"solidity":   "Solidity",
	"vue":        "Vue",
	"html":       "HTML",
	"css":        "CSS",
	"sql":        "SQL",
}

// Words that carry no search value. Kept short on purpose: over-filtering
// destroys meaning, and a rare word is exactly what makes a query precise.
var stopWords = map[string]bool{
	"un": true, "une": true, "des": true, "de": true, "du": true, "le": true,
	"la": true, "les": true, "l": true, "d": true, "en": true, "et": true,
	"ou": true, "a": true, "au": true, "aux": true, "pour": true, "par": true,
	"avec": true, "sans": true, "sur": true, "dans": true, "qui": true,
	"que": true, "je": true, "cherche": true, "veux": true, "trouve": true,
	"trouver": true, "chercher": true, "besoin": true, "faire": true,
	"the": true, "a_en": true, "an": true, "of": true, "for": true, "to": true,
	"in": true, "on": true, "with": true, "and": true, "or": true, "i": true,
	"want": true, "need": true, "find": true, "looking": true, "some": true,
	"est": true, "sont": true, "ce": true, "cette": true, "son": true,
}

// Phrases that ask for recency, mapped to a window in days. Longest first so
// that "tres recent" wins over "recent".
var recencyPhrases = []struct {
	phrase string
	days   int
}{
	{"activement maintenu", 90},
	{"encore maintenu", 180},
	{"toujours maintenu", 180},
	{"recemment mis a jour", 90},
	{"tres recent", 30},
	{"maintenu", 180},
	{"actif", 180},
	{"vivant", 180},
	{"recent", 90},
	{"actively maintained", 90},
	{"still maintained", 180},
	{"maintained", 180},
	{"active", 180},
	{"recent", 90},
}

// Phrases that ask for popularity, mapped to a star floor.
var popularityPhrases = []struct {
	phrase string
	stars  int
}{
	{"tres populaire", 5000},
	{"tres utilise", 5000},
	{"populaire", 500},
	{"connu", 500},
	{"repandu", 500},
	{"serieux", 200},
	{"eprouve", 500},
	{"very popular", 5000},
	{"popular", 500},
	{"widely used", 1000},
	{"well known", 500},
}

// Phrases that reverse a default.
var includeForkPhrases = []string{"y compris les forks", "avec les forks", "including forks"}
var includeArchivedPhrases = []string{"y compris archives", "meme archives", "including archived"}

var starFloorRe = regexp.MustCompile(`(?:plus de|au moins|min|>=?)\s*(\d+)\s*(?:etoiles?|stars?)`)
var wordSplit = regexp.MustCompile(`[^\p{L}\p{N}+#._-]+`)

// Read turns a phrase into an Intent.
//
// Defaults are opinionated and stated: forks and archived repositories are
// excluded unless asked for. Those two categories are the bulk of the noise in
// GitHub's own results, and someone searching for a library to use almost
// never wants either. A default that has to be justified is a default worth
// having; one that surprises is a bug.
func Read(phrase string) model.Intent {
	out := model.Intent{
		Raw:             phrase,
		ExcludeForks:    true,
		ExcludeArchived: true,
	}

	normalised := normalise(phrase)
	rest := normalised

	// Explicit star floor beats the vague popularity words.
	if m := starFloorRe.FindStringSubmatch(rest); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			out.MinStars = n
			out.Explain = append(out.Explain, "au moins "+m[1]+" etoiles")
			rest = strings.Replace(rest, m[0], " ", 1)
		}
	}

	for _, p := range popularityPhrases {
		if out.MinStars > 0 {
			break
		}
		if strings.Contains(rest, p.phrase) {
			out.MinStars = p.stars
			out.Explain = append(out.Explain, "populaire: au moins "+strconv.Itoa(p.stars)+" etoiles")
			rest = strings.Replace(rest, p.phrase, " ", 1)
		}
	}

	for _, p := range recencyPhrases {
		if out.PushedWithinDays > 0 {
			break
		}
		if strings.Contains(rest, p.phrase) {
			out.PushedWithinDays = p.days
			out.Explain = append(out.Explain, "maintenu: pousse depuis moins de "+strconv.Itoa(p.days)+" jours")
			rest = strings.Replace(rest, p.phrase, " ", 1)
		}
	}

	for _, p := range includeForkPhrases {
		if strings.Contains(rest, p) {
			out.ExcludeForks = false
			out.Explain = append(out.Explain, "forks inclus")
			rest = strings.Replace(rest, p, " ", 1)
		}
	}
	for _, p := range includeArchivedPhrases {
		if strings.Contains(rest, p) {
			out.ExcludeArchived = false
			out.Explain = append(out.Explain, "depots archives inclus")
			rest = strings.Replace(rest, p, " ", 1)
		}
	}

	// Multi-word expressions are collapsed first. Translating them word by
	// word would produce noise: "base de donnees" becomes "database data",
	// and "data" alone drags in every repository that mentions it.
	var collapsed []string
	for _, m := range multiWord {
		if strings.Contains(rest, m.phrase) {
			collapsed = append(collapsed, m.term)
			rest = strings.Replace(rest, m.phrase, " ", -1)
		}
	}

	// Language and terms come from the words that remain.
	seenTopic := map[string]bool{}
	seenTerm := map[string]bool{}
	dropped := 0
	translated := 0

	for _, term := range collapsed {
		if !seenTerm[term] {
			seenTerm[term] = true
			out.Terms = append(out.Terms, term)
			if strings.Contains(term, "-") {
				out.Topics = append(out.Topics, term)
				seenTopic[term] = true
			}
		}
	}

	for _, word := range wordSplit.Split(rest, -1) {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		if lang, ok := languages[word]; ok && out.Language == "" {
			out.Language = lang
			out.Explain = append(out.Explain, "langage: "+lang)
			continue
		}
		if stopWords[word] || len(word) < 2 {
			continue
		}
		// Generic nouns describe the kind of thing, not what it does. GitHub
		// combines terms with AND, so one word that matches nothing empties
		// the whole result set: keeping "bibliotheque" is enough to return
		// zero results for a query that would otherwise have worked.
		if generic[word] {
			dropped++
			continue
		}

		term := translate(word)
		if term != word {
			translated++
		}
		if seenTerm[term] {
			continue
		}
		seenTerm[term] = true
		out.Terms = append(out.Terms, term)

		// A hyphenated or dotted word is very likely a topic name as GitHub
		// spells them, so it is worth trying as a topic facet too.
		if strings.ContainsAny(term, "-.") && !seenTopic[term] {
			seenTopic[term] = true
			out.Topics = append(out.Topics, term)
		}
	}

	if dropped > 0 {
		out.Explain = append(out.Explain, plural(dropped, "mot generique ecarte", "mots generiques ecartes"))
	}
	if translated > 0 {
		out.Explain = append(out.Explain, plural(translated, "terme traduit en anglais", "termes traduits en anglais"))
	}

	// Too many ANDed terms is the other way a query returns nothing. Past four
	// content words the phrase is a sentence, not a search, and the odds that
	// every one of them appears in the same repository collapse.
	if len(out.Terms) > 4 {
		out.Terms = out.Terms[:4]
		out.Explain = append(out.Explain, "requete limitee aux quatre termes les plus significatifs")
	}

	if len(out.Terms) == 0 && out.Language != "" {
		// "du rust" alone is a legitimate query: keep the language as the term
		// rather than searching for nothing.
		out.Terms = append(out.Terms, strings.ToLower(out.Language))
	}
	return out
}

// Query renders an Intent as a GitHub search query string.
func Query(in model.Intent) string {
	var parts []string
	parts = append(parts, strings.Join(in.Terms, " "))

	if in.Language != "" {
		parts = append(parts, "language:"+quoteIfNeeded(in.Language))
	}
	for _, t := range in.Topics {
		parts = append(parts, "topic:"+t)
	}
	if in.MinStars > 0 {
		parts = append(parts, "stars:>="+strconv.Itoa(in.MinStars))
	}
	if in.PushedWithinDays > 0 {
		parts = append(parts, "pushed:>="+daysAgo(in.PushedWithinDays))
	}
	if in.ExcludeForks {
		parts = append(parts, "fork:false")
	}
	if in.ExcludeArchived {
		parts = append(parts, "archived:false")
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " ") {
		return "\"" + s + "\""
	}
	return s
}

// normalise lowercases and strips the accents that would otherwise make
// "maintenu" and "maintenu" two different words depending on the keyboard.
func normalise(s string) string {
	s = strings.ToLower(s)
	replacements := map[rune]rune{
		'à': 'a', 'â': 'a', 'ä': 'a',
		'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
		'î': 'i', 'ï': 'i',
		'ô': 'o', 'ö': 'o',
		'ù': 'u', 'û': 'u', 'ü': 'u',
		'ç': 'c',
	}
	var b strings.Builder
	for _, r := range s {
		if rep, ok := replacements[r]; ok {
			b.WriteRune(rep)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
