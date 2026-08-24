// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

// GitHub is not an English-speaking place. A very large share of its
// repositories carry Chinese descriptions, and there is a substantial body of
// Russian, Japanese, Korean, Spanish, Portuguese and German work. Searching
// only in English does not merely miss a few results: it silently excludes
// entire communities, and the exclusion is invisible because the results that
// do come back look perfectly reasonable.
//
// This file widens the net. For the descriptive concepts that actually differ
// between languages, it lists the words those communities use. Purely
// technical tokens are absent on purpose: "yaml", "json", "kubernetes" and
// "grpc" are spelled the same everywhere, so translating them would only
// generate redundant queries.

// multilingual maps an English concept to the words other communities use for
// it. The lists are curated rather than exhaustive: a wrong term is worse than
// a missing one, because it drags in unrelated repositories that then have to
// be filtered out by hand.
var multilingual = map[string][]string{
	"parser": {
		"解析", "パーサー", "파서", "парсер", "analizador", "analisador",
	},
	"encryption": {
		"加密", "暗号化", "암호화", "шифрование", "cifrado", "criptografia", "Verschlüsselung",
	},
	"compression": {
		"压缩", "圧縮", "압축", "сжатие", "compresión", "compressão",
	},
	"network": {
		"网络", "ネットワーク", "네트워크", "сеть", "red", "rede", "Netzwerk",
	},
	"database": {
		"数据库", "データベース", "데이터베이스", "база-данных", "banco-de-dados",
	},
	"security": {
		"安全", "セキュリティ", "보안", "безопасность", "seguridad", "segurança", "Sicherheit",
	},
	"scanner": {
		"扫描", "スキャナ", "스캐너", "сканер", "escáner",
	},
	"monitoring": {
		"监控", "監視", "모니터링", "мониторинг", "monitoreo", "monitoramento",
	},
	"backup": {
		"备份", "バックアップ", "백업", "резервное-копирование", "respaldo",
	},
	"logs": {
		"日志", "ログ", "로그", "логи", "registros",
	},
	"search": {
		"搜索", "検索", "검색", "поиск", "búsqueda", "busca", "Suche",
	},
	"image": {
		"图像", "画像", "이미지", "изображение", "imagen", "imagem", "Bild",
	},
	"video": {
		"视频", "動画", "비디오", "видео", "vídeo",
	},
	"audio": {
		"音频", "音声", "오디오", "аудио", "áudio",
	},
	"game": {
		"游戏", "ゲーム", "게임", "игра", "juego", "jogo", "Spiel",
	},
	"editor": {
		"编辑器", "エディタ", "에디터", "редактор", "editor",
	},
	"terminal": {
		"终端", "ターミナル", "터미널", "терминал",
	},
	"cli": {
		"命令行", "コマンドライン", "명령줄", "командная-строка",
	},
	"framework": {
		"框架", "フレームワーク", "프레임워크", "фреймворк",
	},
	"machine-learning": {
		"机器学习", "機械学習", "머신러닝", "машинное-обучение", "aprendizaje-automático",
	},
	"crawler": {
		"爬虫", "クローラー", "크롤러", "краулер",
	},
	"testing": {
		"测试", "テスト", "테스트", "тестирование", "pruebas", "testes",
	},
	"documentation": {
		"文档", "ドキュメント", "문서", "документация", "documentación", "documentação",
	},
	"authentication": {
		"认证", "認証", "인증", "аутентификация", "autenticación", "autenticação",
	},
	"proxy": {
		"代理", "プロキシ", "프록시", "прокси",
	},
	"deployment": {
		"部署", "デプロイ", "배포", "развертывание", "despliegue", "implantação",
	},
	"container": {
		"容器", "コンテナ", "컨테이너", "контейнер", "contenedor", "contêiner",
	},
	"visualization": {
		"可视化", "可視化", "시각화", "визуализация", "visualización", "visualização",
	},
	"translation": {
		"翻译", "翻訳", "번역", "перевод", "traducción", "tradução",
	},
	"generator": {
		"生成器", "ジェネレータ", "생성기", "генератор", "generador", "gerador",
	},
}

// Variants returns the alternative spellings of a term across languages.
// An unknown term yields nothing, which is correct: most technical tokens are
// spelled identically everywhere and need no variant.
func Variants(term string) []string {
	return multilingual[term]
}

// HasVariants reports whether widening this term would change anything.
func HasVariants(terms []string) bool {
	for _, t := range terms {
		if len(multilingual[t]) > 0 {
			return true
		}
	}
	return false
}
