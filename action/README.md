# GitHub Action

Scannt Dateien auf Prompt Injection und schreibt einen SARIF-Bericht. Die Action
installiert das Paket aus diesem Repo und ruft `pis-scan` auf, sie bringt keine
eigene Musterliste mit. Was hier gemeldet wird, meldet auch die lokale CLI.

## Aufruf

```yaml
name: Prompt Injection

on: [pull_request]

permissions:
  contents: read
  security-events: write     # nur fuer den Upload-Schritt noetig

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: GodModeAI2025/prompt-injection-scanner/action@main
        id: pis
        with:
          paths: 'docs .claude'
          include: 'md,txt,json'
          fail-on: 'HIGH'
          fail-build: 'false'

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.pis.outputs.sarif-file }}
```

Das Hochladen macht der Aufrufer, nicht die Action. `security-events: write` ist
eine Berechtigung, die eine fremde Action nicht stillschweigend voraussetzen
sollte. Mit `fail-build: 'false'` bleibt der Schritt gruen und der Befund
erscheint nur in der Code-Scanning-Ansicht.

## Eingaben

| Eingabe | Standard | Bedeutung |
|---|---|---|
| `paths` | `.` | Dateien oder Verzeichnisse, durch Leerzeichen getrennt |
| `include` | `md,txt,json,yml,yaml` | Endungen, die in einem Verzeichnis geprueft werden |
| `fail-on` | `MEDIUM` | Ab welcher Severity ein Fund zaehlt |
| `sarif-file` | `prompt-injection.sarif` | Zieldatei des Berichts |
| `fail-build` | `true` | Ob ein Fund den Schritt rot macht |
| `python-version` | `3.13` | Python fuer die Installation |

## Ausgaben

| Ausgabe | Bedeutung |
|---|---|
| `sarif-file` | Pfad des geschriebenen Berichts |
| `severity` | Hoechste gefundene Severity, sonst `NONE` |
| `findings` | Zahl der Funde ab der Schwelle |

## Ohne Action

`action/run_action.py` ist der ausfuehrende Teil und laeuft auch lokal, mit
denselben Umgebungsvariablen:

```bash
pip install .
PIS_PATHS=docs PIS_FAIL_ON=HIGH PIS_SARIF=/tmp/pis.sarif python3 action/run_action.py
```

## Severity im Code Scanning

SARIF kennt nur `error`, `warning`, `note`. Die Einstufung von GitHub kommt aus
`properties.security-severity` an der Regel: CRITICAL 9.3, HIGH 7.5, MEDIUM 5.0,
LOW 2.0. Der Fundtext im Bericht wird vorher entschaerft, unsichtbare Zeichen
werden als `<U+XXXX>` geschrieben und die Laenge begrenzt. Ein Bericht landet in
der Oberflaeche eines fremden Repos und oft danach in einem LLM-Kontext; er soll
die Nutzlast beschreiben und nicht weiterreichen.
