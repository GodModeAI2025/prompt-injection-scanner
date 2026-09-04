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
    2   Fund ab der Schwelle, oder der Aufruf konnte nicht vollstaendig geprueft
        werden. Der Aufruf wird blockiert, die Begruendung steht als JSON auf
        stdout und im Klartext auf stderr.
    1   Der Hook selbst ist gescheitert (Eingabe kein JSON, Feld fehlt). Der
        Aufruf laeuft weiter, Claude Code zeigt einen Hinweis.

Zu den Grenzen: `tool_input` wird auf 400 Zeichenketten (Schluessel und Werte),
8 Verschachtelungsebenen und 2000000 Zeichen je Aufruf begrenzt. Ein einzelnes langes Feld wird
in ueberlappenden Fenstern vollstaendig gelesen, solange das Budget reicht; ein
Write von 208000 Zeichen ist also weder abgeschnitten noch ein Grund zum
Blockieren. Wer die Zahlen kennt, kann sein Nutzfeld dahinter legen. Deshalb
endet ein Aufruf, bei dem eine Grenze wirklich etwas aus der Pruefung genommen
hat, nicht still mit 0: er wird blockiert und die Begruendung nennt die Stelle.
`--on-limit warn` gibt die Entscheidung an den Aufrufer zurueck, dann steht der
Hinweis nur auf stderr.

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
# einer vertrauenswuerdigen Quelle. Wer diese Grenzen kennt, kann sie ansteuern:
# 201 Zeichenketten vor dem Nutzfeld oder neun Verschachtelungsebenen genuegten,
# damit der Angriff nicht mehr gescannt wurde. Der Hook endete dann mit 0 und
# ohne Ausgabe, ein durchgelassener Aufruf war von einem sauberen nicht zu
# unterscheiden. Deshalb wird jedes Ueberschreiten gemeldet und standardmaessig
# blockiert; `--on-limit warn` gibt die Entscheidung ab.
_MAX_DEPTH = 8

# Gezaehlt werden Schluessel und Werte, denn beide werden gescannt. Ein Objekt
# mit 200 Feldern liegt damit genau auf der Grenze, so wie vor v0.2.0 auch.
_MAX_STRINGS = 400

# Fenstergroesse eines einzelnen Scanlaufs, nicht die Grenze des Feldes. Ein
# langes Feld wird in Fenstern vollstaendig gelesen; die Ueberlappung sorgt
# dafuer, dass ein Muster an der Naht nicht zerfaellt (das laengste Muster ist
# weit unter 4096 Zeichen lang).
_MAX_CHARS = 200000
_WINDOW_OVERLAP = 4096

# Gesamtbudget je Aufruf. Bis v0.2.0 stand hier eine Grenze je Feld, und ein
# harmloser Write von 208000 Zeichen endete mit "deny". Das war eine
# Fehl-Ablehnung an einer voellig gewoehnlichen Dateigroesse und der erste
# Grund, den Hook wieder auszubauen. Gescannt wird deshalb bis zum Budget
# vollstaendig; erst was dahinter liegt, faellt aus der Pruefung und wird
# gemeldet. Gemessen kostet die Engine rund 2 Mikrosekunden je Zeichen, das
# Budget also gut vier Sekunden im schlimmsten Fall, bei 30 Sekunden Timeout.
_MAX_TOTAL_CHARS = 2000000


def _has_content(value):
    """Traegt der Wert ueberhaupt Text, den der Scanner lesen wuerde?"""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list, tuple)):
        return bool(value)
    return False


def _fenster(path, text):
    """Ein langes Feld in ueberlappende Scanfenster zerlegen."""
    if len(text) <= _MAX_CHARS:
        return [(path, text)]
    schritt = _MAX_CHARS - _WINDOW_OVERLAP
    stuecke = []
    start = 0
    while start < len(text):
        stueck = text[start:start + _MAX_CHARS]
        stuecke.append(('%s[%d:%d]' % (path, start, start + len(stueck)), stueck))
        if start + _MAX_CHARS >= len(text):
            break
        start += schritt
    return stuecke


def collect_strings(value, path='tool_input', depth=0, collected=None, skipped=None,
                    budget=None, felder=None):
    """Alle Zeichenketten aus einem verschachtelten Werkzeug-Argument.

    Ein Angriff steckt selten im Feld, das man erwartet, und selten in einem
    Wert. Deshalb wird jedes String-Feld gescannt und nicht nur `command` oder
    `content`, und die Schluessel eines Objekts werden mitgelesen: ein Aufruf
    wie `{"Ignore all previous instructions": "ok"}` ist ein gueltiges
    `tool_input` und lief vorher ohne Ausgabe mit Exit 0 durch.

    Ein Feld, das laenger als ein Scanfenster ist, wird in ueberlappenden
    Fenstern vollstaendig gelesen. Die Fenster zaehlen als ein Feld gegen
    `_MAX_STRINGS`, ihre Zeichen zaehlen gegen `_MAX_TOTAL_CHARS`.

    Rueckgabe: `(felder, uebergangen)`. `uebergangen` nennt jede Stelle, an der
    eine Grenze etwas aus der Pruefung genommen hat. Gezaehlt wird, was
    tatsaechlich wegfaellt, nicht das Erreichen der Grenze: genau
    `_MAX_STRINGS` Zeichenketten sind vollstaendig geprueft, die naechste nicht.
    """
    if collected is None:
        collected = []
    if skipped is None:
        skipped = []
    if budget is None:
        budget = [_MAX_TOTAL_CHARS]
    if felder is None:
        felder = [0]

    if depth > _MAX_DEPTH:
        if _has_content(value):
            skipped.append('%s liegt tiefer als %d Ebenen und wurde nicht geprueft'
                           % (path, _MAX_DEPTH))
        return collected, skipped

    if isinstance(value, str):
        if not value.strip():
            return collected, skipped
        if felder[0] >= _MAX_STRINGS:
            skipped.append('%s faellt hinter die Grenze von %d Zeichenketten und '
                           'wurde nicht geprueft' % (path, _MAX_STRINGS))
            return collected, skipped
        felder[0] += 1
        text = value
        if len(text) > budget[0]:
            skipped.append('%s ist %d Zeichen lang, geprueft wurden die ersten %d '
                           '(Gesamtbudget %d Zeichen je Aufruf)'
                           % (path, len(text), budget[0], _MAX_TOTAL_CHARS))
            text = text[:budget[0]]
        budget[0] -= len(text)
        if text:
            collected.extend(_fenster(path, text))
    elif isinstance(value, dict):
        for key in sorted(value):
            # Der Schluessel selbst ist Text aus derselben unsicheren Quelle.
            if isinstance(key, str) and key.strip():
                collect_strings(key, '%s.%s (Schluessel)' % (path, key[:40]),
                                depth + 1, collected, skipped, budget, felder)
            collect_strings(value[key], '%s.%s' % (path, key), depth + 1,
                            collected, skipped, budget, felder)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            collect_strings(item, '%s[%d]' % (path, index), depth + 1,
                            collected, skipped, budget, felder)
    return collected, skipped


def evaluate(payload, threshold=MIN_REPORTABLE_SEVERITY):
    """Liefert (blockieren, begruendung, treffer, uebergangen) fuer einen Aufruf.

    `blockieren` bezieht sich nur auf gefundene Injections. Was mit einem
    unvollstaendig geprueften Aufruf geschieht, entscheidet `main()` anhand von
    `--on-limit`; die Begruendung nennt das Uebergangene in beiden Faellen.
    """
    tool_name = payload.get('tool_name') or 'unbekannt'
    fields, skipped = collect_strings(payload.get('tool_input', {}))

    hits = []
    for path, text in fields:
        result = scan(text, source=path, threshold=threshold)
        for finding in meaningful_findings(result.findings, threshold):
            hits.append((path, finding, result))

    if not hits:
        return False, '', [], skipped

    hits.sort(key=lambda h: -SEVERITY_ORDER.get(h[1].severity, 0))
    worst_path, worst, worst_result = hits[0]
    reason = (
        'Prompt Injection im Aufruf von %s blockiert. '
        'Hoechste Severity %s (Kategorie %s, Confidence %s) in %s, Score %d. '
        'Treffer: %s. Insgesamt %d Fund/Funde ab %s.'
        % (tool_name, worst.severity, worst.category, worst.confidence, worst_path,
           worst_result.score, redact(worst.pattern_matched), len(hits), threshold)
    )
    if skipped:
        reason += ' Ausserdem unvollstaendig geprueft: %s.' % '; '.join(skipped)
    return True, reason, hits, skipped


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='pis-hook-pretooluse',
        description='PreToolUse-Hook fuer Claude Code. Liest den geplanten '
                    'Werkzeugaufruf als JSON von stdin und blockiert bei einem Fund.',
        epilog='Exit-Codes: 0 durchlassen, 2 blockieren, 1 Hook gescheitert.')
    parser.add_argument('--fail-on', choices=SEVERITIES, default=MIN_REPORTABLE_SEVERITY,
                        help='Ab welcher Severity blockiert wird. Standard: %s. '
                             'LOW blockiert zusaetzlich bei Funden, die der Kontext auf '
                             'Confidence LOW gedrueckt hat.' % MIN_REPORTABLE_SEVERITY)
    parser.add_argument('--on-limit', choices=('block', 'warn'), default='block',
                        help='Was geschieht, wenn eine der Grenzen (%d Zeichenketten, '
                             '%d Verschachtelungsebenen, %d Zeichen je Aufruf) etwas aus '
                             'der Pruefung nimmt. "block": den Aufruf ablehnen, weil er '
                             'nicht vollstaendig geprueft werden konnte (Standard). '
                             '"warn": nur auf stderr melden und durchlassen.'
                             % (_MAX_STRINGS, _MAX_DEPTH, _MAX_TOTAL_CHARS))
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

    block, reason, _hits, skipped = evaluate(payload, args.fail_on)

    if not block and skipped:
        note = ('Der Aufruf von %s konnte nicht vollstaendig geprueft werden: %s.'
                % (payload.get('tool_name') or 'unbekannt', '; '.join(skipped)))
        if args.on_limit == 'warn':
            sys.stderr.write('pis-hook-pretooluse: %s Durchgelassen wegen '
                             '--on-limit warn.\n' % note)
            return EXIT_ALLOW
        reason = note + (' Ein Aufruf, dessen Nutzfeld hinter einer Grenze liegt, '
                         'ist von einem sauberen nicht zu unterscheiden; deshalb '
                         'blockiert der Hook hier. Mit --on-limit warn laeuft er '
                         'stattdessen mit einem Hinweis durch.')
        block = True
    elif not block:
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
