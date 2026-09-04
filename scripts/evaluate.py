#!/usr/bin/env python3
"""Misst die Erkennungs-Engine gegen eine Test-Suite.

Die Engine selbst steht seit Welle 5 im Paket `prompt_injection_scanner`
(Modul `engine`). Diese Datei ist nur noch die Messschleife darum: sie laedt
die Suite, ruft `scan_text()` auf und rechnet TP, FP, TN, FN aus.

Damit teilen Skill, CLI, Hook, Action und dieser Evaluator dieselben Muster und
dieselbe Schwelle. Vorher lag die Regel, ab wann ein Fund als Erkennung zaehlt,
nur hier in der Schleife; jeder weitere Aufrufer haette sich eine eigene gebaut.

Aufruf:

    python3 scripts/evaluate.py
    python3 scripts/evaluate.py --test-suite <datei> --output <datei>

Exit-Codes: 0 alle Faelle wie erwartet, 1 mindestens ein Fehlurteil,
2 falscher Aufruf.
"""

import argparse
import json
import os
import sys

# Das Paket liegt eine Ebene ueber dieser Datei: im Repo neben scripts/, im
# entpackten Release-Archiv genauso. Der Pfad kommt bewusst an den Anfang von
# sys.path und nicht in einen ImportError-Fallback. Sonst misst der Evaluator
# eine per pip installierte Version statt der Arbeitskopie, und genau diese
# Drift zwischen zwei Kopien derselben Muster soll hier nicht entstehen.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prompt_injection_scanner import engine

# Namen, die dieses Modul frueher selbst definiert hat. `import evaluate as E`
# aus scripts/test_context_regression.py und aus fremden Skripten laeuft damit
# unveraendert weiter.
Finding = engine.Finding
PATTERNS = engine.PATTERNS
SEVERITY_ORDER = engine.SEVERITY_ORDER
SEVERITY_SCORE = engine.SEVERITY_SCORE
CONFIDENCE_ORDER = engine.CONFIDENCE_ORDER
MIN_ACTIONABLE_CONFIDENCE = engine.MIN_ACTIONABLE_CONFIDENCE
context_signals = engine.context_signals
is_educational_context = engine.is_educational_context
is_code_defense_context = engine.is_code_defense_context
is_benign_documentation = engine.is_benign_documentation
citation_spans = engine.citation_spans
is_cited = engine.is_cited
is_operative = engine.is_operative
damp = engine.damp
is_actionable = engine.is_actionable
check_base64 = engine.check_base64
check_unicode_injection = engine.check_unicode_injection
scan_text = engine.scan_text
scan = engine.scan
get_highest = engine.get_highest
calc_score = engine.calc_score
is_detected = engine.is_detected
meaningful_findings = engine.meaningful_findings



def run(suite_path, output_path):
    """Misst die Engine gegen eine Suite. Rueckgabe: Zahl der Fehlurteile (FP+FN)."""
    with open(suite_path) as f:
        evals = json.load(f)
    
    results = []
    tp = fp = tn = fn = 0
    sev_correct = 0
    cat_hits = cat_total = 0
    
    for ev in evals['evals']:
        text = ev['prompt']
        for sp in [':\n\n', ':\n']:
            if sp in text:
                text = text.split(sp, 1)[1]
                break
        
        result = engine.scan(text, source=str(ev['id']))
        findings = result.findings
        highest = result.highest_severity
        score = result.score
        detected = result.detected
        
        is_mal = ev['is_malicious']
        if is_mal and detected: tp += 1
        elif is_mal and not detected: fn += 1
        elif not is_mal and not detected: tn += 1
        else: fp += 1
        
        exp = ev['expected_severity']
        if (exp in ('NONE','INFO') and highest in ('NONE','INFO')) or highest == exp or abs(SEVERITY_ORDER.get(highest,0) - SEVERITY_ORDER.get(exp,0)) <= 1:
            sev_correct += 1
        
        if ev['expected_categories']:
            cat_total += 1
            if set(ev['expected_categories']).intersection(set(f.category for f in findings)):
                cat_hits += 1
        
        results.append({'eval_id': ev['id'], 'category': ev['category'], 'is_malicious': is_mal,
            'expected_severity': exp, 'detected': detected, 'highest_severity': highest,
            'score': score, 'num_findings': len(findings),
            'finding_categories': list(set(f.category for f in findings)),
            'correct_detection': is_mal == detected})
    
    total = len(evals['evals'])
    mal = sum(1 for e in evals['evals'] if e['is_malicious'])
    ben = total - mal
    prec = round(tp/(tp+fp)*100,1) if tp+fp else 0
    rec = round(tp/(tp+fn)*100,1) if tp+fn else 0
    f1 = round(2*tp/(2*tp+fp+fn)*100,1) if 2*tp+fp+fn else 0
    
    print("=" * 60)
    print("ITERATION 5 - EVALUATION RESULTS")
    print("=" * 60)
    print(f"\nTests: {total} ({mal} malicious, {ben} benign)")
    print(f"\nTP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"Recall:     {rec}%")
    print(f"Precision:  {prec}%")
    print(f"F1:         {f1}%")
    print(f"FP Rate:    {round(fp/ben*100,1) if ben else 0}%")
    print(f"Accuracy:   {round((tp+tn)/total*100,1)}%")
    print(f"Sev Acc:    {round(sev_correct/total*100,1)}%")
    print(f"Cat Hits:   {round(cat_hits/cat_total*100,1) if cat_total else 0}%")
    
    missed = [r for r in results if not r['correct_detection']]
    if missed:
        print(f"\n--- Missed ({len(missed)}) ---")
        for m in missed:
            s = "FN" if m['is_malicious'] else "FP"
            print(f"  [{s}] #{m['eval_id']} {m['category']}: det={m['detected']}, sev={m['highest_severity']}, cats={m['finding_categories']}")
    
    exact = sum(1 for r in results if r['highest_severity'] == r['expected_severity'] or (r['expected_severity'] in ('NONE','INFO') and r['highest_severity'] in ('NONE','INFO')))
    print(f"\nExact Severity Match: {exact}/{total} ({round(exact/total*100,1)}%)")
    
    with open(output_path, 'w') as f:
        json.dump({'summary': {'tp':tp,'tn':tn,'fp':fp,'fn':fn,'precision':prec,'recall':rec,'f1':f1}, 'results': results, 'missed': missed}, f, indent=2)
    print(f"\nResults saved to {output_path}")

    return fp + fn


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        prog='evaluate.py',
        description='Prueft die Pattern-Engine gegen eine Test-Suite. '
                    'Exit-Code 0, wenn jeder Fall wie erwartet bewertet wird, '
                    'sonst 1. Unbekannte Argumente sind ein Fehler (Exit-Code 2).')
    parser.add_argument('--test-suite', default=os.path.join(here, 'test-suite.json'),
                        metavar='DATEI',
                        help='Test-Suite im Format {"evals": [...]}. '
                             'Standard: scripts/test-suite.json')
    parser.add_argument('--output', default=os.path.join(here, 'eval-results.json'),
                        metavar='DATEI',
                        help='Zieldatei fuer den Ergebnisbericht. '
                             'Standard: scripts/eval-results.json')
    args = parser.parse_args(argv)

    try:
        failures = run(args.test_suite, args.output)
    except FileNotFoundError as exc:
        parser.error(f'Datei nicht gefunden: {exc.filename}')
    except (ValueError, KeyError, TypeError) as exc:
        parser.error(f'Test-Suite nicht verwertbar ({args.test_suite}): {exc}')

    if failures:
        print(f"\nFEHLGESCHLAGEN: {failures} Fall/Faelle falsch bewertet.")
        return 1
    print("\nBESTANDEN: alle Faelle wie erwartet bewertet.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
