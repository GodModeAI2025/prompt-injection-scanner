"""SARIF 2.1.0 aus Scan-Ergebnissen.

SARIF ist das Format, das GitHub Code Scanning liest. Ein Lauf wird zu einem
`runs`-Eintrag mit einem Regelkatalog (eine Regel je erkannter Kategorie) und
einem `results`-Eintrag je Fund.

Zwei Dinge, die GitHub braucht und die leicht fehlen:

* `properties.security-severity` an der Regel. Ohne diese Zahl zeigt die
  Code-Scanning-Ansicht jede Warnung gleich streng an.
* `partialFingerprints`. Ohne sie zaehlt GitHub denselben Fund nach jeder
  Zeilenverschiebung als neu.

Der Fundtext wird nicht roh uebernommen. Ein SARIF-Bericht landet in der
Oberflaeche eines fremden Repos und oft danach in einem LLM-Kontext; der
Angreifertext darin bleibt Angreifertext. Deshalb `redact()` aus der Engine:
unsichtbare Zeichen werden benannt, die Laenge ist begrenzt, alles steht in
einer Zeile. Ein lesbarer Klartextbefehl bleibt lesbar; entschaerft ist die
Kodierung, nicht der Satz.
"""

import hashlib
import json

from .engine import SEVERITY_ORDER, meaningful_findings, redact

# `redact()` steht seit v0.2.0 in der Engine, weil auch `ScanResult.to_dict()`
# sie braucht und ein Import von hier nach dort ein Kreis waere. Der Name bleibt
# hier erreichbar: `from prompt_injection_scanner.sarif import redact` laeuft
# unveraendert weiter.
__all__ = ['TOOL_NAME', 'INFORMATION_URI', 'redact', 'build_report', 'dumps']


TOOL_NAME = 'Prompt Injection Scanner'
INFORMATION_URI = 'https://github.com/GodModeAI2025/prompt-injection-scanner'

# SARIF kennt error, warning, note, none. Die Severity-Stufen des Scanners
# bilden darauf ab; security-severity ist die Zahl, an der GitHub die
# Einstufung festmacht (9.0 und hoeher gilt dort als kritisch).
_LEVEL = {
    'CRITICAL': ('error', '9.3'),
    'HIGH': ('error', '7.5'),
    'MEDIUM': ('warning', '5.0'),
    'LOW': ('note', '2.0'),
    'INFO': ('note', '0.5'),
}

def _rule_id(finding):
    return 'PIS-' + finding.category.replace('Kat. ', 'KAT').replace(' ', '')


def _line_and_column(text, offset):
    """1-basierte Zeile und Spalte zu einem Zeichenversatz."""
    if offset is None or offset < 0 or offset > len(text):
        return None
    line = text.count('\n', 0, offset) + 1
    line_start = text.rfind('\n', 0, offset) + 1
    return line, offset - line_start + 1


def _region(text, finding):
    start = _line_and_column(text, finding.start)
    if start is None:
        return None
    region = {'startLine': start[0], 'startColumn': start[1]}
    end = _line_and_column(text, finding.end)
    if end is not None:
        region['endLine'] = end[0]
        region['endColumn'] = end[1]
    return region


def _fingerprint(uri, finding):
    raw = '|'.join([uri, finding.category, finding.severity, finding.pattern_matched])
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


def build_report(scans, version='unbekannt', threshold=None):
    """SARIF-Objekt aus einer Liste von (ScanResult, Text, URI).

    `threshold` begrenzt auf Funde ab dieser Severity. Ohne Angabe gilt die
    Schwelle der Engine, also dieselbe wie fuer Exit-Code und Hook.
    """
    rules = {}
    results = []

    for result, text, uri in scans:
        findings = (meaningful_findings(result.findings, threshold) if threshold
                    else meaningful_findings(result.findings))
        for finding in findings:
            rule_id = _rule_id(finding)
            level, security_severity = _LEVEL.get(finding.severity, ('warning', '5.0'))
            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'name': rule_id.replace('-', ''),
                    'shortDescription': {'text': 'Prompt Injection %s' % finding.category},
                    'fullDescription': {
                        'text': 'Muster der Kategorie %s aus references/detection-patterns.md.'
                                % finding.category},
                    'help': {
                        'text': 'Kategorienbeschreibung in references/detection-patterns.md.',
                        'markdown': '[Kategorienbeschreibung](%s/blob/main/references/'
                                    'detection-patterns.md)' % INFORMATION_URI,
                    },
                    'defaultConfiguration': {'level': level},
                    'properties': {
                        'security-severity': security_severity,
                        'tags': ['security', 'prompt-injection', finding.category],
                    },
                }

            location = {'physicalLocation': {'artifactLocation': {'uri': uri}}}
            region = _region(text, finding)
            if region:
                location['physicalLocation']['region'] = region

            results.append({
                'ruleId': rule_id,
                'level': level,
                'message': {
                    'text': '%s (%s, Confidence %s): %s'
                            % (finding.category, finding.severity, finding.confidence,
                               redact(finding.pattern_matched)),
                },
                'locations': [location],
                'partialFingerprints': {'primaryLocationLineHash': _fingerprint(uri, finding)},
                'properties': {
                    'confidence': finding.confidence,
                    'severity': finding.severity,
                    'score': result.score,
                },
            })

    # Stabile Reihenfolge: gleiche Eingabe, gleiche Datei.
    ordered_rules = [rules[key] for key in sorted(rules)]
    results.sort(key=lambda r: (-SEVERITY_ORDER.get(r['properties']['severity'], 0),
                                r['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                                r['ruleId']))

    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': TOOL_NAME,
                'version': version,
                'informationUri': INFORMATION_URI,
                'rules': ordered_rules,
            }},
            'results': results,
        }],
    }


def dumps(scans, version='unbekannt', threshold=None):
    return json.dumps(build_report(scans, version, threshold), indent=2, ensure_ascii=False)
