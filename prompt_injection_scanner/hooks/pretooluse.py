"""PreToolUse-Hook fuer Claude Code: `pis-hook-pretooluse`.

Der Hook sitzt zwischen der Entscheidung des Modells und der Ausfuehrung des
Werkzeugs. Er liest den geplanten Aufruf als JSON von der Standardeingabe,
scannt jeden Text darin mit derselben Engine wie CLI und Evaluator und
blockiert, wenn ein Fund ab der Schwelle darin steckt.

Eingabe (Auszug aus dem Hook-Vertrag von Claude Code):

    {"hook_event_name": "PreToolUse",
     "tool_name": "Bash",
     "tool_input": {"command": "...", ...}}

Ausgabe und Exit-Codes:

    0   kein Fund. Keine Entscheidung, der normale Berechtigungsweg gilt.
    2   Fund ab der Schwelle. Der Aufruf wird blockiert, die Begruendung steht
        als JSON auf stdout und im Klartext auf stderr.
    1   Der Hook selbst ist gescheitert (Eingabe kein JSON, Feld fehlt). Der
        Aufruf laeuft weiter, Claude Code zeigt einen Hinweis.

Warum nicht die Exit-Codes von `pis-scan`: dort steht 4 fuer CRITICAL. Claude
Code liest alles ausser 0 und 2 als "Hook kaputt" und laesst den Aufruf laufen.
Ein CRITICAL-Fund waere dann genau der Fall, der durchginge. Der Hook ruft die
Bibliothek deshalb direkt auf und uebersetzt selbst.

Einbau in `~/.claude/settings.json` oder `.claude/settings.json`:

    {"hooks": {"PreToolUse": [{"matcher": "Bash|Write|Edit|WebFetch|Task",
                               "hooks": [{"type": "command",
                                          "command": "pis-hook-pretooluse"}]}]}}

Ein vollstaendiges Beispiel liegt in `examples/claude-code-settings.json`.
"""

import argparse
import json
import sys

from ..engine import (
    MIN_REPORTABLE_SEVERITY,
    SEVERITY_ORDER,
    meaningful_findings,
    scan,
)
from ..sarif import redact

EXIT_ALLOW = 0
EXIT_HOOK_ERROR = 1
EXIT_BLOCK = 2

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

# Tiefe und Menge begrenzen: tool_input kommt aus einem Modelllauf, nicht aus
# einer vertrauenswuerdigen Quelle.
_MAX_DEPTH = 8
_MAX_STRINGS = 200
_MAX_CHARS = 200000


def collect_strings(value, path='tool_input', depth=0, collected=None):
    """Alle Zeichenketten aus einem verschachtelten Werkzeug-Argument.

    Ein Angriff steckt selten im Feld, das man erwartet. Deshalb wird jedes
    String-Feld gescannt und nicht nur `command` oder `content`.
    """
    if collected is None:
        collected = []
    if len(collected) >= _MAX_STRINGS or depth > _MAX_DEPTH:
        return collected
    if isinstance(value, str):
        if value.strip():
            collected.append((path, value[:_MAX_CHARS]))
    elif isinstance(value, dict):
        for key in sorted(value):
            collect_strings(value[key], '%s.%s' % (path, key), depth + 1, collected)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            collect_strings(item, '%s[%d]' % (path, index), depth + 1, collected)
    return collected


def evaluate(payload, threshold=MIN_REPORTABLE_SEVERITY):
    """Liefert (blockieren, begruendung, treffer) fuer einen Hook-Aufruf."""
    tool_name = payload.get('tool_name') or 'unbekannt'
    fields = collect_strings(payload.get('tool_input', {}))

    hits = []
    for path, text in fields:
        result = scan(text, source=path, threshold=threshold)
        for finding in meaningful_findings(result.findings, threshold):
            hits.append((path, finding, result))

    if not hits:
        return False, '', []

    hits.sort(key=lambda h: -SEVERITY_ORDER.get(h[1].severity, 0))
    worst_path, worst, worst_result = hits[0]
    reason = (
        'Prompt Injection im Aufruf von %s blockiert. '
        'Hoechste Severity %s (Kategorie %s, Confidence %s) in %s, Score %d. '
        'Treffer: %s. Insgesamt %d Fund/Funde ab %s.'
        % (tool_name, worst.severity, worst.category, worst.confidence, worst_path,
           worst_result.score, redact(worst.pattern_matched), len(hits), threshold)
    )
    return True, reason, hits


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='pis-hook-pretooluse',
        description='PreToolUse-Hook fuer Claude Code. Liest den geplanten '
                    'Werkzeugaufruf als JSON von stdin und blockiert bei einem Fund.',
        epilog='Exit-Codes: 0 durchlassen, 2 blockieren, 1 Hook gescheitert.')
    parser.add_argument('--fail-on', choices=SEVERITIES, default=MIN_REPORTABLE_SEVERITY,
                        help='Ab welcher Severity blockiert wird. Standard: %s.'
                             % MIN_REPORTABLE_SEVERITY)
    parser.add_argument('--tools', metavar='NAME[,NAME...]', default=None,
                        help='Nur diese Werkzeugnamen pruefen. Ohne Angabe alle. '
                             'Die Vorauswahl gehoert eigentlich in den matcher der '
                             'settings.json, das hier ist die Notbremse.')
    args = parser.parse_args(argv)

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError as error:
        sys.stderr.write('pis-hook-pretooluse: Eingabe ist kein JSON (%s).\n' % error)
        return EXIT_HOOK_ERROR
    if not isinstance(payload, dict):
        sys.stderr.write('pis-hook-pretooluse: Eingabe ist kein JSON-Objekt.\n')
        return EXIT_HOOK_ERROR

    if args.tools:
        wanted = {name.strip() for name in args.tools.split(',') if name.strip()}
        if payload.get('tool_name') not in wanted:
            return EXIT_ALLOW

    block, reason, _hits = evaluate(payload, args.fail_on)
    if not block:
        return EXIT_ALLOW

    decision = {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': reason,
        }
    }
    sys.stdout.write(json.dumps(decision, ensure_ascii=False) + '\n')
    sys.stderr.write(reason + '\n')
    return EXIT_BLOCK


if __name__ == '__main__':
    sys.exit(main())
