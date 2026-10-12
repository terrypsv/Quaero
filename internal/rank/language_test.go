// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package rank

import "testing"

func TestDetectLanguage(t *testing.T) {
	cases := map[string]string{
		"A fast YAML parser for Go":    LangEnglish,
		"SSH honeypot":                 LangEnglish,
		"Port scanner written in Rust": LangEnglish,
		"Pot de miel SSH minimal qui journalise les identifiants tentés": LangFrench,
		"Un outil pour scanner les ports d'une machine":                  LangFrench,
		"Herramienta para escanear puertos de una red":                   LangSpanish,
		"Ferramenta para análise de tráfego de rede":                     LangPortuguese,
		"Ein schneller Portscanner für das Netzwerk":                     LangGerman,
		"Uno strumento per la scansione delle porte":                     LangItalian,
		"Công cụ quét cổng mạng":                                         LangVietnamese,
		"一个快速的端口扫描器":                                                     LangChinese,
		"高速なポートスキャナー":                                                    LangJapanese,
		"빠른 포트 스캐너":                                                      LangKorean,
		"Быстрый сканер портов":                                          LangRussian,
		"Швидкий сканер портів для мережі":                               LangUkrainian,
		"":          "",
		"12345 !!!": LangOther,
	}
	for text, want := range cases {
		if got := DetectLanguage(text); got != want {
			t.Errorf("DetectLanguage(%q) = %q, attendu %q", text, got, want)
		}
	}
}

// Les noms techniques sont anglais partout: une description francaise qui
// en contient beaucoup reste francaise.
func TestFrancaisTechnique(t *testing.T) {
	text := "Scanner de ports TCP et UDP rapide, avec export JSON et support IPv6"
	if got := DetectLanguage(text); got != LangFrench {
		t.Errorf("DetectLanguage(%q) = %q", text, got)
	}
}
