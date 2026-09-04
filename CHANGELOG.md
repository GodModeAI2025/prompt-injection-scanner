# Changelog

Die Versionsnummer steht genau an einer Stelle: in der Datei `VERSION` im Wurzelverzeichnis.
Der oberste Eintrag hier muss dieselbe Nummer tragen, sonst wird die CI rot
(`python3 scripts/package.py <ziel> --verify`). Beim Tag prüft der Release-Workflow zusätzlich,
dass `vX.Y.Z` zu `VERSION` passt.

Die Zählung beginnt bei 0.1.0, weil es das erste Release des Repos ist. Ältere Bezeichnungen wie
"v4" oder "Iteration 6" in Commit-Nachrichten, im Docstring von `scripts/evaluate.py` und in der
README beziehen sich auf Entwicklungsstände der Pattern-Bibliothek, nicht auf veröffentlichte Pakete.
Solange die Hauptversion 0 ist, können sich Ausgabeformat und Kategorienschnitt zwischen zwei
Versionen ändern.

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
