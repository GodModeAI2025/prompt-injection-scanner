"""Kommandozeile des Scanners: `pis-scan`.

Liest Dateien, Standardeingabe oder einen Text vom Aufruf und meldet, was die
Engine findet. Die Muster kommen aus `prompt_injection_scanner.engine`, es gibt
hier keine zweite Erkennung und keine zweite Schwelle.

Die Schwelle `--fail-on` steuert, welche Funde zaehlen. Ab MEDIUM zaehlen nur
Funde mit Confidence MEDIUM oder hoeher; bei LOW zaehlen auch die Funde, die der
Kontext abgewertet hat. Ein zitierter CRITICAL-Fund bleibt damit im Standardlauf
still ("Severity INFO, Score 99", Exit 0) und wird mit `--fail-on LOW` als
"Severity CRITICAL, Score 75" mit Exit 4 gemeldet. Kopfzeile, Score, JSON-Feld
`highest_severity` und Exit-Code folgen derselben Schwelle; wuerden sie das
nicht, meldete der Kopf INFO, waehrend der Exit-Code CRITICAL sagt.

Exit-Codes richten sich nach der hoechsten gefundenen Severity, damit eine
Pipeline ohne JSON-Parsen entscheiden kann:

    0   nichts ab der Schwelle
    1   LOW
    2   MEDIUM
    3   HIGH
    4   CRITICAL
    64  falscher Aufruf
    65  Eingabe nicht lesbar

Damit weicht die CLI von `scripts/evaluate.py` und `scripts/package.py` ab, die
2 fuer einen falschen Aufruf benutzen. Hier ist die 2 an MEDIUM vergeben, also
uebernimmt 64 die Rolle (EX_USAGE aus sysexits.h, 65 ist EX_DATAERR).
"""

import argparse
import json
import os
import sys

from . import __version__
from .engine import (
    MIN_REPORTABLE_SEVERITY,
    SEVERITY_ORDER,
    meaningful_findings,
    scan,
)
from . import sarif as sarif_module

EXIT_CLEAN = 0
EXIT_USAGE = 64
EXIT_INPUT = 65

# Severity zu Exit-Code. Bewusst lueckenlos aufsteigend, damit `test $? -ge 3`
# als "HIGH oder schlimmer" funktioniert.
EXIT_BY_SEVERITY = {'NONE': 0, 'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

_MAX_BYTES = 5 * 1024 * 1024


class _Parser(argparse.ArgumentParser):
    """argparse endet bei einem Aufruffehler mit 2. Hier gehoert 2 zu MEDIUM."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write('%s: Fehler: %s\n' % (self.prog, message))
        raise SystemExit(EXIT_USAGE)


def _read(path):
    if path == '-':
        return sys.stdin.read(), '<stdin>'
    if not os.path.isfile(path):
        raise IOError('%s ist keine Datei.' % path)
    size = os.path.getsize(path)
    if size > _MAX_BYTES:
        raise IOError('%s ist %d Bytes gross, die Grenze liegt bei %d.'
                      % (path, size, _MAX_BYTES))
    with open(path, 'r', encoding='utf-8', errors='replace') as handle:
        return handle.read(), path


def _text_report(results, threshold):
    lines = []
    for result in results:
        findings = meaningful_findings(result.findings, threshold)
        verdict = 'BEFUND' if findings else 'sauber'
        lines.append('%s  %s  Severity %s, Score %d, %d Fund/Funde ab %s'
                     % (verdict, result.source, result.highest_severity, result.score,
                        len(findings), threshold))
        for finding in sorted(findings,
                              key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
            lines.append('    %-8s %-8s %-8s %s'
                         % (finding.severity, finding.confidence, finding.category,
                            sarif_module.redact(finding.pattern_matched)))
    return '\n'.join(lines)


def main(argv=None):
    parser = _Parser(
        prog='pis-scan',
        description='Prueft Text auf Prompt Injection. Dieselbe Engine wie der '
                    'Skill und der Evaluator.',
        epilog='Exit-Codes: 0 nichts ab der Schwelle, 1 LOW, 2 MEDIUM, 3 HIGH, '
               '4 CRITICAL, 64 falscher Aufruf, 65 Eingabe nicht lesbar.')
    parser.add_argument('paths', nargs='*', metavar='DATEI',
                        help='Zu pruefende Dateien. "-" liest die Standardeingabe. '
                             'Ohne Angabe und ohne --text wird die Standardeingabe gelesen.')
    parser.add_argument('--text', metavar='TEXT', default=None,
                        help='Text direkt aus dem Aufruf statt aus einer Datei.')
    parser.add_argument('--format', choices=('text', 'json', 'sarif'), default='text',
                        help='Ausgabeformat. Standard: text.')
    parser.add_argument('--output', metavar='DATEI', default=None,
                        help='Bericht in eine Datei schreiben statt nach stdout.')
    parser.add_argument('--fail-on', choices=SEVERITIES, default=MIN_REPORTABLE_SEVERITY,
                        help='Ab welcher Severity ein Fund zaehlt. Standard: %s, '
                             'dieselbe Schwelle, ab der der Evaluator einen Fall als '
                             'erkannt zaehlt. LOW zaehlt zusaetzlich die Funde, die der '
                             'Kontext auf Confidence LOW gedrueckt hat; das ist der '
                             'Schalter, mit dem die Abwertung sichtbar wird.'
                             % MIN_REPORTABLE_SEVERITY)
    parser.add_argument('--quiet', action='store_true',
                        help='Nur den Exit-Code liefern, keine Ausgabe.')
    parser.add_argument('--version', action='version',
                        version='pis-scan %s' % __version__)
    args = parser.parse_args(argv)

    if args.text is not None and args.paths:
        parser.error('--text und Dateien schliessen sich aus.')

    sources = []
    try:
        if args.text is not None:
            sources.append((args.text, '<text>'))
        elif args.paths:
            for path in args.paths:
                sources.append(_read(path))
        else:
            sources.append((sys.stdin.read(), '<stdin>'))
    except IOError as error:
        sys.stderr.write('pis-scan: %s\n' % error)
        return EXIT_INPUT

    results = [scan(text, source=name, threshold=args.fail_on) for text, name in sources]

    if args.format == 'sarif':
        report = sarif_module.dumps(
            [(result, text, name) for result, (text, name) in zip(results, sources)],
            version=__version__, threshold=args.fail_on)
    elif args.format == 'json':
        report = json.dumps({
            'version': __version__,
            'fail_on': args.fail_on,
            'results': [result.to_dict() for result in results],
        }, indent=2, ensure_ascii=False)
    else:
        report = _text_report(results, args.fail_on)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as handle:
                handle.write(report + '\n')
        except OSError as error:
            sys.stderr.write('pis-scan: Bericht nicht schreibbar: %s\n' % error)
            return EXIT_INPUT
        if not args.quiet:
            sys.stdout.write('Bericht in %s\n' % args.output)
    elif not args.quiet:
        sys.stdout.write(report + '\n')

    limit = SEVERITY_ORDER.get(args.fail_on, 2)
    worst = 'NONE'
    for result in results:
        for finding in meaningful_findings(result.findings, args.fail_on):
            if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(worst, -1):
                worst = finding.severity
    if SEVERITY_ORDER.get(worst, -1) < limit:
        return EXIT_CLEAN
    return EXIT_BY_SEVERITY.get(worst, EXIT_CLEAN)


if __name__ == '__main__':
    sys.exit(main())
