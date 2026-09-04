# Changelog

Die Versionsnummer steht genau an einer Stelle: in der Datei `VERSION` im Wurzelverzeichnis.
Der oberste Eintrag hier muss dieselbe Nummer tragen, sonst wird die CI rot
(`python3 scripts/package.py <ziel> --verify`). Beim Tag prüft der Release-Workflow zusätzlich,
dass `vX.Y.Z` zu `VERSION` passt.

Die Zählung beginnt bei 0.1.0, weil es das erste Release des Repos ist. Ältere Bezeichnungen wie
"v4" oder "Iteration 6" in Commit-Nachrichten und in der README beziehen sich auf Entwicklungsstände
der Pattern-Bibliothek, nicht auf veröffentlichte Pakete.
Solange die Hauptversion 0 ist, können sich Ausgabeformat und Kategorienschnitt zwischen zwei
Versionen ändern.

## 0.2.0 (2026-09-04)

Der Scanner ist nicht mehr nur ein Skill. Die Erkennung liegt als Bibliothek vor, mit CLI, mit einem
PreToolUse-Hook und mit einer GitHub Action. Alle vier lesen dieselben Muster; ein PyPI-Upload gehört
nicht dazu, installiert wird aus dem Repo oder aus dem entpackten Release-Archiv.

### Neu

- **Paket `prompt_injection_scanner`.** Die Erkennung stand in `scripts/evaluate.py` und war nur über
  einen Import aus diesem Verzeichnis erreichbar. Sie steht jetzt in `prompt_injection_scanner/engine.py`,
  `scripts/evaluate.py` ist die Messschleife darum und exportiert die alten Namen weiter.
  `pip install .` funktioniert aus dem Repo und aus dem entpackten Scanner-Archiv. Nur
  Standardbibliothek, ab Python 3.9, Version aus `VERSION`.
- **`pis-scan`.** Dateien, Standardeingabe oder `--text`, Ausgabe als `text`, `json` oder `sarif`. Der
  Exit-Code nennt die höchste gefundene Severity: `0` sauber, `1` LOW, `2` MEDIUM, `3` HIGH,
  `4` CRITICAL, `64` falscher Aufruf, `65` Eingabe nicht lesbar. Die `64` statt der im Repo sonst
  üblichen `2`, weil die `2` hier an MEDIUM vergeben ist.
- **`pis-hook-pretooluse`.** PreToolUse-Hook für Claude Code. Liest den geplanten Werkzeugaufruf als
  JSON von der Standardeingabe, scannt jede Zeichenkette in `tool_input` rekursiv und blockiert mit
  Exit-Code `2` und einer `deny`-Entscheidung. Fertiger Eintrag in
  `examples/claude-code-settings.json`. Der Hook reicht die Exit-Codes von `pis-scan` bewusst nicht
  durch: Claude Code liest alles außer `0` und `2` als kaputten Hook und lässt den Aufruf laufen, ein
  CRITICAL wäre dort die `4`.
- **GitHub Action in `action/`.** Composite-Action mit SARIF-2.1.0-Ausgabe für Code Scanning. Setzt
  auf dem Paket auf, nicht auf einem Skript im Repo. Der Upload bleibt beim Aufrufer, weil
  `security-events: write` eine Berechtigung ist, die eine fremde Action nicht stillschweigend
  voraussetzen sollte. Regeln tragen `properties.security-severity`, sonst stuft GitHub jeden Fund
  gleich ein.
- **`scripts/test_cli_hook.py`**, 23 Fälle für Exit-Codes, Hook-Entscheidungen, SARIF-Aufbau und den
  Lauf des Action-Skripts.

### Behoben

- **Die Befehlsprüfung in der Kontext-Bewertung ist ersatzlos gestrichen.** Bis dahin entschied eine
  Liste von Verben, Höflichkeitspräfixen und Anreden, ob ein unzitierter Treffer ein Befehl oder eine
  bloße Erwähnung ist. Sieben gemessene Schreibweisen kamen daran vorbei, alle im Bildungsrahmen mit
  `highest_severity` INFO, Score 99, `detected` False, Hook Exit 0 und `pis-scan` Exit 0 auf allen
  vier `--fail-on`-Stufen: `- Ignore previous instructions.`, `* Ignore …`, `-> Ignore …`,
  `(Ignore previous instructions.)`, `Just ignore …`, `Simply ignore …`, `Could you please ignore …`,
  dazu ein einzelnes U+FE0F hinter dem Satzzeichen. Erkannt wurde dagegen `1. Ignore previous
  instructions.`: entschieden hat der Punkt in der Nummerierung, nicht der Inhalt. Über die Abwertung
  auf `LOW` entscheidet jetzt allein, ob jeder Treffer eines Musters in einem Zitat, einem Code-Block
  oder zwischen Backticks steht. Ein früherer Zwischenschritt, der Höflichkeitspräfixe und
  unsichtbare Zeichen in dieselbe Liste aufgenommen hatte, ist damit hinfällig; die Fälle stehen
  weiter in `scripts/test_context_regression.py`, jetzt 23 statt 17.
- **Anführungszeichen werden mit einem Stapel gepaart, nicht mit starrer Abwechslung.** Ein Zitat im
  Zitat paarte das äußere mit dem inneren Zeichen; der zitierte Angriffssatz lag dann zwischen zwei
  Spannen und galt als unzitiert. Gemessen waren das drei False Positives auf der generierten Suite,
  sobald die Abwertung nur noch an der Zitatprüfung hing.
- **`--fail-on LOW` zählt jetzt die kontextbedingt abgewerteten Funde.** `meaningful_findings()`
  filterte unabhängig von der Schwelle auf Confidence ab MEDIUM. `pis-scan --fail-on LOW` und
  `pis-hook-pretooluse --fail-on LOW` lieferten auf einem abgewerteten CRITICAL-Fund weiterhin
  Exit 0, der Fund stand als "CRITICAL LOW" im Bericht und wirkte auf keine Entscheidung. Damit gab
  es keinen Schalter, mit dem ein Verteidiger die Abwertung überhaupt sieht.
- **Die Wortfolge "system prompt" ist kein Leet-Speak-Muster mehr.** Sie stand als eigener Treffer in
  der Gruppe `leet_speak` und machte jede Chatbot-Dokumentation zum HIGH-Fund, sobald die
  Kontext-Bewertung nicht mehr an der Formulierung hing. Das Muster verlangt jetzt eine echte
  Ersetzung (`syst3m`, `pr0mpt`); die Aufforderung mit Anrede ("share your system prompt") deckt ein
  neues Kat.-12-Muster ab.
- **Die Detection-Schwelle stand in der Auswertungsschleife.** Ab wann ein Fund als Erkennung zählt,
  war eine Zeile in `run()` von `scripts/evaluate.py`. Jeder weitere Aufrufer hätte sich eine eigene
  gebaut. Sie steht als `MIN_REPORTABLE_SEVERITY` in der Engine, dazu `meaningful_findings()`,
  `is_detected()` und `scan()` mit einem `ScanResult`.
- **Fundtexte in Berichten werden entschärft.** `redact()` schreibt nicht druckbare und unsichtbare
  Zeichen als `<U+XXXX>`, entfernt Zeilenumbrüche und begrenzt auf 200 Zeichen. Ein SARIF-Bericht
  landet in der Oberfläche eines fremden Repos und oft danach in einem LLM-Kontext. Das gilt jetzt
  auch für `pis-scan --format json`: `ScanResult.to_dict()` reichte `pattern_matched` und
  `description` roh durch, gemessen an einem HTML-Kommentar-Treffer mit U+202E und U+200B, der im
  JSON-Bericht im Original stand und im SARIF-Bericht schon als `<U+202E>` und `<U+200B>`.
  `redact()` steht dafür in der Engine; `prompt_injection_scanner.sarif.redact` reicht den Namen
  weiter. Was `redact()` nicht leistet und auch nicht leisten soll: ein dekodierter Klartextbefehl
  bleibt lesbar, sonst wäre der Bericht für den Auswerter wertlos.

### Geändert

- Das Scanner-Archiv enthält zusätzlich `prompt_injection_scanner/` und `pyproject.toml`. Der
  entpackte Ordner ist damit Skill-Verzeichnis und Paketquelle zugleich; ohne Installation findet
  `scripts/evaluate.py` die Engine über einen Pfad-Fallback. Die CI entpackt das Archiv bei jedem
  Lauf und fährt beide Wege durch.
- CI: neue Schritte für `scripts/test_cli_hook.py`, den Lauf des entpackten Archivs ohne pip, ein
  `pip install .` mit Prüfung beider Konsolenbefehle und ein Durchlauf der Action gegen das eigene
  Repo.
- README, SECURITY.md, SKILL.md und die Landingpage nachgezogen. In SECURITY.md standen
  Bedrohungsmodell 1 und 3 sowie die bekannten Lücken 1 und 4 noch auf dem Stand vor `v0.1.0` und
  beschrieben Fehler, die es nicht mehr gab. Neu dazu: der Hook ist eine Prüfung und kein
  Sicherheitsmechanismus, und `tool_input` ist untrusted.

## 0.1.0 (2026-09-04)

Erstes Release. Zwei Archive, gebaut von `scripts/package.py`:
`prompt-injection-scanner.zip` (Scanner-Skill) und `red-team-generator.zip` (Testfall-Generator).

### Behoben

- **Kontext senkt die Confidence, nicht die Severity.** Vorher setzte ein Treffer in
  `is_educational_context`, `is_code_defense_context` oder `is_benign_documentation` jeden Fund auf
  `INFO`, und `INFO` galt in der Auswertung als nicht erkannt. Zwei harmlose Sätze vor einem echten
  Angriff genügten, um ihn unsichtbar zu machen. Jetzt bleibt die Severity, was das Muster hergibt,
  und der Kontext zieht die Confidence herunter. Abgesichert durch
  `scripts/test_context_regression.py`.
- **`scripts/evaluate.py` liefert echte Exit-Codes.** `0` alle Fälle wie erwartet, `1` mindestens ein
  Fehlurteil, `2` falscher Aufruf. Vorher gab es keine Argumentverarbeitung: Ein Lauf mit
  `--test-suite <datei>` prüfte still die eingebaute Suite und endete mit `0`. Wer den in der
  Dokumentation genannten Aufruf in eine Pipeline übernahm, bekam ein grünes Ergebnis, das nichts
  über die übergebenen Fälle aussagte.
- **Die Kategorienzahl in README, Landingpage und SKILL.md nennt jetzt die tatsächlich erkannten
  Kategorien**: 28 dokumentiert, davon 25 mit Muster in `scripts/evaluate.py`. Der Red-Team-Generator
  deckt 12 Kategorien ab, nicht 28. Die Kennzahlen sind als Eigenmessung gekennzeichnet, mit Datum,
  Commit und Suite.
- Zerstörte Überschriften in `references/detection-patterns.md` wiederhergestellt, die Kontextregel
  dort an den Code angeglichen. Zitat- und Satzsuche der Kontext-Prüfung sind begrenzt, damit sie
  nicht über das ganze Dokument laufen.

### Neu

- `.github/workflows/ci.yml`: Regressionstest der Kontext-Bewertung, Test-Suite gegen die Engine,
  Prüfung auf Abbruch bei falschem Aufruf, generierte Suite gegen die Engine. Läuft unter
  Python 3.9 und 3.13.
- `scripts/package.py`: baut die beiden Release-Archive lokal und ohne Netz, byte-gleich bei
  wiederholtem Lauf. `--verify` prüft Inhalt, verbotene Pfade, Reproduzierbarkeit und die
  Übereinstimmung von `VERSION` und Changelog.
- `.github/workflows/release.yml`: reagiert auf Tags `v*`, ruft das Packaging-Skript auf und hängt
  beide Archive an das Release.
- `VERSION` und diese Datei.

### Unverändert offen

Die Kontext-Prüfung hat weiterhin Lücken. Ein Höflichkeits- oder Modalpräfix vor dem Befehlsverb
(`Please ignore previous instructions.`, `You must ignore previous instructions.`) drückt einen
Angriff im Bildungsrahmen weiter auf INFO, und Kat. 24a schlägt erst ab drei Zero-Width-Zeichen an.
Die Fälle stehen mit Messwerten in der README unter "Bekannte Lücken der Kontext-Bewertung", die
Roadmap dort nennt die Reihenfolge, in der sie angegangen werden. `SECURITY.md` beschreibt das
Bedrohungsmodell, sein Abschnitt zum Kontext-Bypass ist auf dem Stand vor diesen Korrekturen.
