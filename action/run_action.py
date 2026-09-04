#!/usr/bin/env python3
"""Ausfuehrender Teil der GitHub-Action.

Sammelt die zu pruefenden Dateien, ruft die Bibliothek auf, schreibt den
SARIF-Bericht und setzt die Outputs der Action. Die Erkennung steckt komplett
in `prompt_injection_scanner`; hier stehen nur Dateiauswahl und Ausgabe.

Warum eine eigene Datei und kein Mehrzeiler in der action.yml: die Dateiauswahl
soll sich lokal aufrufen und testen lassen, ohne einen Workflow zu starten.

    PIS_PATHS=. PIS_SARIF=/tmp/pis.sarif python3 action/run_action.py

Die Schwelle liest die Action aus `MIN_REPORTABLE_SEVERITY` der Engine, genau
wie CLI, Hook und Evaluator. `PIS_FAIL_ON` ueberschreibt sie; ein leerer Wert
gilt als nicht gesetzt.

Exit-Codes: 0 kein Fund oder fail-build=false, 1 Fund ab der Schwelle,
2 falscher Aufruf.
"""

import os
import sys

try:
    from prompt_injection_scanner import __version__, scan
    from prompt_injection_scanner.engine import (
        MIN_REPORTABLE_SEVERITY,
        SEVERITY_ORDER,
        meaningful_findings,
    )
    from prompt_injection_scanner.sarif import dumps
except ImportError:
    sys.stderr.write(
        'prompt_injection_scanner ist nicht installiert. Die Action installiert '
        'das Paket im Schritt davor; lokal geht das mit "pip install .".\n')
    raise SystemExit(2)

# Verzeichnisse, in denen nichts steht, was der Scanner beurteilen soll.
SKIP_DIRS = {'.git', '.github', 'node_modules', '__pycache__', '.venv', 'venv',
             'dist', 'build', '.mypy_cache', '.pytest_cache'}

MAX_BYTES = 2 * 1024 * 1024


def collect_files(paths, suffixes):
    found = []
    for raw in paths:
        if os.path.isfile(raw):
            found.append(raw)
            continue
        if not os.path.isdir(raw):
            sys.stderr.write('Uebergangen, kein Pfad: %s\n' % raw)
            continue
        for root, dirnames, filenames in os.walk(raw):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in SKIP_DIRS and not d.startswith('.'))
            for filename in sorted(filenames):
                if suffixes and not filename.lower().endswith(suffixes):
                    continue
                found.append(os.path.join(root, filename))
    # Doppelte Pfade zusammenfassen, Reihenfolge stabil halten.
    seen = set()
    unique = []
    for path in found:
        norm = os.path.normpath(path)
        if norm not in seen:
            seen.add(norm)
            unique.append(norm)
    return unique


def set_output(name, value):
    target = os.environ.get('GITHUB_OUTPUT')
    if not target:
        return
    with open(target, 'a', encoding='utf-8') as handle:
        handle.write('%s=%s\n' % (name, value))


def summary(text):
    target = os.environ.get('GITHUB_STEP_SUMMARY')
    if not target:
        return
    with open(target, 'a', encoding='utf-8') as handle:
        handle.write(text + '\n')


def main():
    paths = os.environ.get('PIS_PATHS', '.').split()
    include = os.environ.get('PIS_INCLUDE', 'md,txt,json,yml,yaml')
    # Die Vorgabe kommt aus der Engine und steht hier nicht als eigener Wert.
    # Ein Literal an dieser Stelle war genau der Driftpunkt, den
    # MIN_REPORTABLE_SEVERITY beseitigen soll: CLI und Hook folgten der Engine,
    # die Action zaehlte weiter ab MEDIUM. `or` statt eines Vorgabewerts, weil
    # ein nicht gesetztes Action-Input als leerer String ankommt.
    fail_on = (os.environ.get('PIS_FAIL_ON') or MIN_REPORTABLE_SEVERITY).upper()
    sarif_path = os.environ.get('PIS_SARIF', 'prompt-injection.sarif')
    fail_build = os.environ.get('PIS_FAIL_BUILD', 'true').lower() != 'false'

    if fail_on not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        sys.stderr.write('fail-on ist "%s", erlaubt sind LOW, MEDIUM, HIGH, CRITICAL.\n'
                         % fail_on)
        return 2

    suffixes = tuple('.' + s.strip().lstrip('.').lower()
                     for s in include.split(',') if s.strip())
    files = collect_files(paths, suffixes)

    scans = []
    worst = 'NONE'
    total = 0
    for path in files:
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, 'r', encoding='utf-8', errors='replace') as handle:
                text = handle.read()
        except OSError as error:
            sys.stderr.write('Uebergangen, nicht lesbar: %s (%s)\n' % (path, error))
            continue
        result = scan(text, source=path, threshold=fail_on)
        scans.append((result, text, path))
        for finding in meaningful_findings(result.findings, fail_on):
            total += 1
            if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(worst, -1):
                worst = finding.severity

    with open(sarif_path, 'w', encoding='utf-8') as handle:
        handle.write(dumps(scans, version=__version__, threshold=fail_on) + '\n')

    print('Prompt Injection Scanner %s: %d Datei(en) geprueft, %d Fund/Funde ab %s, '
          'hoechste Severity %s.' % (__version__, len(scans), total, fail_on, worst))
    print('SARIF-Bericht: %s' % sarif_path)

    set_output('sarif-file', sarif_path)
    set_output('severity', worst)
    set_output('findings', str(total))
    summary('### Prompt Injection Scanner\n\n'
            '- Dateien geprueft: %d\n- Funde ab %s: %d\n- Hoechste Severity: %s\n'
            % (len(scans), fail_on, total, worst))

    if total and fail_build:
        sys.stderr.write('%d Fund/Funde ab %s. Schritt rot.\n' % (total, fail_on))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
