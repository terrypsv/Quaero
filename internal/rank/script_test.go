// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package rank

import (
	"testing"

	"github.com/terrypsv/Quaero/internal/model"
)

func TestDetectScript(t *testing.T) {
	cases := map[string]string{
		"A fast YAML parser for Go": ScriptLatin,
		"Un analyseur YAML rapide":  ScriptLatin,
		"一个快速的 YAML 解析器":            ScriptHan,
		"高速な YAML パーサー":             ScriptJapanese,
		"빠른 YAML 파서":                ScriptKorean,
		"Быстрый парсер YAML":       ScriptCyrillic,
		"محلل YAML سريع":            ScriptArabic,
		"מנתח YAML מהיר":            ScriptHebrew,
		"":                          ScriptUnknown,
		"12345 !!! ...":             ScriptUnknown,
	}
	for text, want := range cases {
		t.Run(text, func(t *testing.T) {
			if got := DetectScript(text); got != want {
				t.Errorf("DetectScript(%q) = %q, want %q", text, got, want)
			}
		})
	}
}

// Le japonais melange kana et caracteres chinois: les kana tranchent, sinon
// tout le japonais serait classe comme chinois.
func TestKanaDecidesJapaneseOverHan(t *testing.T) {
	if got := DetectScript("日本語のパーサー"); got != ScriptJapanese {
		t.Errorf("= %q, want japonais", got)
	}
}

// Une description majoritairement anglaise avec un ideogramme reste anglaise:
// la classer autrement la rangerait dans un filtre ou personne ne la cherche.
func TestDominantScriptWins(t *testing.T) {
	text := "A comprehensive and very fast YAML parsing library for the Go programming language 中"
	if got := DetectScript(text); got != ScriptLatin {
		t.Errorf("= %q, want latin", got)
	}
}

// Les caracteres latins fuient dans toutes les descriptions par les noms de
// projets et les URL: une ecriture non latine minoritaire reste decisive.
func TestNonLatinMinorityStillCounts(t *testing.T) {
	text := "YAML 解析器 for Go"
	if got := DetectScript(text); got != ScriptHan {
		t.Errorf("= %q, want chinois", got)
	}
}

func TestTagScriptsFillsEveryRepo(t *testing.T) {
	repos := []model.Repo{
		{Description: "A parser"},
		{Description: "解析器"},
		{Description: ""},
	}
	TagScripts(repos)
	if repos[0].Script != ScriptLatin || repos[1].Script != ScriptHan || repos[2].Script != ScriptUnknown {
		t.Errorf("ecritures = %q, %q, %q", repos[0].Script, repos[1].Script, repos[2].Script)
	}
}
