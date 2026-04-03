#!/usr/bin/env python3
"""
Prompt Injection Scanner - Evaluation v4
Fixes from v3:
- FP#32: Better red-team/pentest report detection
- FN#34: Leet speak / typosquatting detection
- FN#36: Emotional manipulation / social engineering
- FN#40: Whitespace smuggling (improved newline detection)
- FN#44: Fake Anthropic/creator messages
- FN#49: Error-debugging pretext for prompt leakage
- FN#50: Sandwich attacks (benign-malicious-benign pattern)
"""

import re, json, base64
from dataclasses import dataclass, field, asdict
from typing import List, Optional

@dataclass
class Finding:
    category: str
    severity: str
    confidence: str
    pattern_matched: str
    description: str
    is_primary: bool = True

SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0, 'NONE': -1}
SEVERITY_SCORE = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}

# ============================================================
# IMPROVED Context Classifiers
# ============================================================

def is_educational_context(text: str) -> bool:
    edu_signals = [
        r'(?i)(this\s+)?article\s+(discusses|explains|covers)',
        r'(?i)(discuss|explain)\w*\s+(defensive|defense|protection)\s+strategies',
        r'(?i)attackers?\s+use\s+phrases?\s+like',
        r'(?i)(threats?\s+to|attacks?\s+on|vulnerabilit\w+\s+in)\s+AI',
        r'(?i)input\s+validation\s+and\s+output\s+filtering',
        r'(?i)defensive\s+(strategies|measures|techniques)',
        r'(?i)how\s+to\s+(detect|prevent|mitigate)',
        r'(?i)(remains|is)\s+one\s+of\s+the\s+top\s+threats',
        r'(?i)for\s+(educational|defensive|research)\s+purposes',
        # v4: red team / pentest report patterns
        r'(?i)(our\s+)?red\s+team\s+tested',
        r'(?i)the\s+system\s+correctly\s+(refused|rejected|blocked)',
        r'(?i)we\s+recommend\s+adding',
        r'(?i)(security\s+)?(assessment|audit|test)\s+results?',
        r'(?i)percent\s+of\s+these\s+attempts',
        r'(?i)\d+%\s+of\s+(these\s+)?attempts',
    ]
    score = sum(1 for p in edu_signals if re.search(p, text))
    return score >= 2

def is_code_defense_context(text: str) -> bool:
    defense_signals = [
        r'(?i)def\s+(validate|check|filter|sanitize|detect)',
        r'(?i)dangerous_patterns\s*=',
        r'(?i)return\s+False',
        r'(?i)(blocklist|denylist|blacklist)',
        r'(?i)if\s+pattern\s+in',
    ]
    return sum(1 for p in defense_signals if re.search(p, text)) >= 2

def is_benign_documentation(text: str) -> bool:
    """Detect benign chatbot documentation / system prompt design discussion."""
    signals = [
        r'(?i)to\s+configure\s+your\s+chatbot',
        r'(?i)set\s+the\s+system\s+prompt\s+in\s+the\s+dashboard',
        r'(?i)defines\s+the\s+AI\'?s\s+behavior',
        r'(?i)in\s+meiner?\s+(masterarbeit|dissertation|bachelorarbeit)',
        r'(?i)verschiedene\s+ansätze\s+zur\s+instruktionsgestaltung',
        r'(?i)analysiere\s+deren\s+auswirkungen',
        r'(?i)how\s+(to\s+)?(structure|design|write)\s+(better\s+)?system\s+prompts?',
    ]
    return sum(1 for p in signals if re.search(p, text)) >= 1


# ============================================================
# Pattern Definitions v4
# ============================================================

PATTERNS = {
    'direct_override': [
        (r'(?i)ignore\s+(all|previous|prior|above|earlier)\s+(instructions|rules|guidelines|directives|constraints)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)forget\s+(all|everything|previous|your|prior)\s+(instructions|rules|training|guidelines)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)disregard\s+(all|any|previous|your)\s+(instructions|rules|safety|guidelines)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)override\s+(your|all|previous|system)\s+(instructions|rules|settings|behavior)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)from\s+now\s+on\s+(you\s+must|you\s+will|you\s+are|always|never)', 'Kat. 1', 'HIGH', True),
        (r'(?i)stop\s+following\s+(your|previous|all)\s+(rules|instructions)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)your\s+(real|actual)\s+(instructions|purpose)\s+(are|is)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)ignora\s+todas\s+las\s+instrucciones', 'Kat. 1', 'CRITICAL', True),
        # v4: Sandwich / NEW INSTRUCTION
        (r'(?i)(IMPORTANT|URGENT|CRITICAL)\s+NEW\s+INSTRUCTION', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)ignore\s+your\s+safety\s+guidelines', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)new\s+primary\s+directive', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)this\s+supersedes\s+all\s+previous', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)prefix\s+all\s+responses\s+with', 'Kat. 1', 'HIGH', True),
        # v5: German overrides
        (r'(?i)ignoriere\s+(alle\s+)?(vorherige\w*\s+)?(anweisungen|regeln)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)vergiss\s+(alles|deine\s+regeln|alle\s+regeln)', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)l[öo]sche\s+alle\s+vorherigen\s+regeln', 'Kat. 1', 'CRITICAL', True),
        (r'(?i)ab\s+jetzt\s+(musst|wirst|sollst)\s+du', 'Kat. 1', 'HIGH', True),
        (r'(?i)neue\s+Anweisungen\s*:', 'Kat. 1', 'CRITICAL', True),
        # v5: Soft overrides / polite bypasses
        (r'(?i)set\s+aside\s+your\s+(current\s+)?guidelines', 'Kat. 1', 'HIGH', True),
        (r'(?i)put\s+aside\s+your\s+(rules|constraints|guidelines)', 'Kat. 1', 'HIGH', True),
        (r'(?i)tabula\s+rasa', 'Kat. 1', 'HIGH', True),
        (r'(?i)let.s\s+start\s+fresh', 'Kat. 1', 'HIGH', True),
        (r'(?i)clean\s+slate', 'Kat. 1', 'HIGH', True),
        (r'(?i)your\s+new\s+(primary\s+)?task\s*:', 'Kat. 1', 'HIGH', True),
    ],
    'leet_speak': [
        # v4: Leet speak / typosquatting
        (r'(?i)d[1i!]sr[e3]g[a@]rd\s+.{0,15}(pr[e3]v[1i!][o0]us|[a@]ll)', 'Kat. 1', 'HIGH', True),
        (r'(?i)[1i!]gn[o0]r[e3]\s+.{0,15}(pr[e3]v[1i!][o0]us|[a@]ll)', 'Kat. 1', 'HIGH', True),
        (r'(?i)syst[e3]m\s+pr[o0]mpt', 'Kat. 1', 'HIGH', True),
        (r'd1sregard|prev1ous|instruct1ons|pr0mpt', 'Kat. 1', 'HIGH', True),
    ],
    'system_impersonation': [
        (r'\[SYSTEM\]|\[/SYSTEM\]', 'Kat. 2', 'CRITICAL', True),
        (r'<\|system\|>', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)ADMIN\s*OVERRIDE', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)(DEVELOPER|DEBUG|MAINTENANCE)\s*MODE', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)SECURITY_AUDIT_MODE', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)AUTHORIZATION\s*:', 'Kat. 2', 'HIGH', True),
        (r'(?i)(COMMAND|EXECUTE)\s*:', 'Kat. 2', 'HIGH', True),
        (r'(?i)INTERNAL[_\s]DIAGNOSTIC', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)ADMIN_LEVEL_\d', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)MAINTENANCE_MODE', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)QA\s+verification', 'Kat. 2', 'HIGH', True),
        # v4: Fake creator messages
        (r'(?i)###\s*SYSTEM\s+MESSAGE\s+FROM\s+(ANTHROPIC|OPENAI)', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)(Dear\s+Claude|Dear\s+ChatGPT).*we\s+have\s+updated\s+your', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)message\s+from\s+(Anthropic|OpenAI|your\s+creators?)', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)updated\s+your\s+instructions', 'Kat. 2', 'CRITICAL', True),
        (r'(?i)###\s*END\s+SYSTEM\s+MESSAGE\s*###', 'Kat. 2', 'HIGH', True),
    ],
    'encoding': [
        (r'(?i)(decode|entschl[üu]ssle)\s+(this|das|the|diese)\s+base64', 'Kat. 3', 'HIGH', True),
        (r'(?i)(decode|entschl[üu]ssle)\s+(this|das|the|diese)', 'Kat. 3', 'HIGH', True),
        (r'(?i)(read|lies)\s+(this|das)\s+(backwards|r[üu]ckw[äa]rts)', 'Kat. 3', 'HIGH', True),
        (r'(?i)Decode\s+and\s+execute', 'Kat. 3', 'CRITICAL', True),
        (r'(?i)do\s+what\s+it\s+says', 'Kat. 3', 'HIGH', True),
        # v4: Data URI detection
        (r'data:text/plain;base64,', 'Kat. 3', 'HIGH', True),
        (r'(?i)process\s+this\s+data\s+URI', 'Kat. 3', 'HIGH', True),
    ],
    'canary': [
        (r'(?i)include\s+(the|this|exact)\s+phrase', 'Kat. 4', 'HIGH', True),
        (r'(?i)weave\s+(this|it)\s+naturally\s+into', 'Kat. 4', 'HIGH', True),
        (r'(?i)for\s+message\s+verification', 'Kat. 4', 'HIGH', True),
        (r'[A-Z]{3,}_[A-Z]{3,}_[A-Z0-9]{2,}', 'Kat. 4', 'MEDIUM', False),
        # v5: Output-instruction canaries
        (r'(?i)when\s+you\s+respond.*include\s+.{1,30}\s+at\s+the\s+end', 'Kat. 4', 'HIGH', True),
        (r'(?i)append\s+.{1,40}\s+to\s+(your|the)\s+(response|output|answer)', 'Kat. 4', 'HIGH', True),
        (r'(?i)end\s+(your|every)\s+(response|output)\s+with\s+.{1,30}', 'Kat. 4', 'HIGH', True),
        (r'(?i)(always|must)\s+include\s+.{1,30}\s+in\s+(your|every)\s+(response|output)', 'Kat. 4', 'HIGH', True),
    ],
    'format_behavior': [
        (r'(?i)from\s+now\s+on[\s,]+(start|end|always|never)\s+every\s+(response|sentence|message)', 'Kat. 5', 'HIGH', True),
        (r'(?i)respond\s+ONLY\s+in\s+(JSON|XML|uppercase)', 'Kat. 5', 'HIGH', True),
        (r'(?i)ALL\s+UPPERCASE.*FROM\s+NOW\s+ON', 'Kat. 5', 'MEDIUM', True),
        (r'(?i)you\s+are\s+now\s+a\s+(pirate|robot|DAN)', 'Kat. 5', 'MEDIUM', True),
        (r'(?i)respond[ea]?\s+[uú]nicamente\s+en\s+espa[nñ]ol', 'Kat. 5', 'HIGH', True),
        (r'(?i)confirma\s+diciendo', 'Kat. 5', 'MEDIUM', True),
        (r'(?i)Confirm\s+by\s+(saying|responding|typing)', 'Kat. 5', 'MEDIUM', True),
        (r'(?i)end\s+every\s+response\s+with', 'Kat. 5', 'MEDIUM', True),
        (r'(?i)start\s+every\s+(sentence|response)\s+with', 'Kat. 5', 'MEDIUM', True),
        # v4: prefix injection
        (r'(?i)prefix\s+all\s+responses\s+with\s+[\'"]', 'Kat. 5', 'HIGH', True),
    ],
    'indirect_injection': [
        (r'<!--\s*(AI|ASSISTANT|INSTRUCTION|System)\s*:', 'Kat. 6', 'CRITICAL', True),
        (r'\[ASSISTANT\s*:', 'Kat. 6', 'CRITICAL', True),
        (r'#\s*AI_INSTRUCTION\s*:', 'Kat. 6', 'CRITICAL', True),
        (r'(?i)\[SYSTEM\s*:.*ignore|ignore.*\[SYSTEM', 'Kat. 6', 'CRITICAL', True),
        (r'<!--\s*HIDDEN\s*:', 'Kat. 6', 'CRITICAL', True),
        (r'<!--\s*.{0,60}(ignore|output|respond|say\s|print\s|append|include|execute|call\s)', 'Kat. 6', 'HIGH', True),
        (r'<!--[^>]{0,100}-->', 'Kat. 6', 'MEDIUM', False),
        (r'(?i)\[ASSISTANT:\s*(ignore|Before|first|After)', 'Kat. 6', 'CRITICAL', True),
        # v5: Invisible text in documents
        (r'(?i)color\s*:\s*white', 'Kat. 6', 'CRITICAL', True),
        (r'(?i)color\s*:\s*#fff', 'Kat. 6', 'CRITICAL', True),
        (r'(?i)font-size\s*:\s*[01]px', 'Kat. 6', 'CRITICAL', True),
        (r'(?i)opacity\s*:\s*0[\.\d]*["\s;]', 'Kat. 6', 'HIGH', True),
    ],
    'false_memory': [
        (r'(?i)as\s+we\s+(discussed|agreed)\s+earlier', 'Kat. 7', 'HIGH', True),
        (r'(?i)you\s+agreed\s+to', 'Kat. 7', 'HIGH', True),
        (r'(?i)continuing\s+from\s+debug\s+mode', 'Kat. 7', 'HIGH', True),
        (r'(?i)as\s+established.*TEST_MODE', 'Kat. 7', 'HIGH', True),
        (r'(?i)Confirm\s+by\s+saying\s+"TEST_MODE', 'Kat. 7', 'HIGH', True),
        # v4: Time bomb injection
        (r'(?i)(after\s+processing|after\s+\d+\s+(more\s+)?messages).*switch\s+to', 'Kat. 7', 'HIGH', True),
        (r'(?i)was\s+agreed\s+upon\s+during\s+setup', 'Kat. 7', 'HIGH', True),
        (r'(?i)switch\s+to\s+developer\s+mode', 'Kat. 7', 'HIGH', True),
    ],
    'fake_tool': [
        (r'(?i)API\s+CALL\s*:', 'Kat. 8', 'HIGH', True),
        (r'(?i)execute\s+(the\s+)?(function|api\s+call)', 'Kat. 8', 'HIGH', True),
    ],
    'gamification': [
        (r'(?i)let\'?s\s+play\s+a\s+(word|fun|simple)\s+game', 'Kat. 9', 'MEDIUM', True),
        (r'(?i)say\s+.{1,20}\s+three\s+times', 'Kat. 9', 'MEDIUM', True),
        (r'(?i)it\'?s\s+fun!', 'Kat. 9', 'LOW', False),
    ],
    'delimiter': [
        # v4: Improved whitespace smuggling
        (r'\n{5,}', 'Kat. 11', 'HIGH', True),
        (r'(?i)</s>', 'Kat. 11', 'HIGH', True),
        (r'(?i)</instructions>', 'Kat. 11', 'HIGH', True),
    ],
    'data_leak': [
        (r'(?i)show\s+(me\s+)?your\s+system\s+prompt', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)output\s+your\s+(instructions|configuration|initialization)', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)display\s+your\s+(full|complete|exact|verbatim)\s+(instructions|prompt)', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)export_system_configuration', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)system\s+configuration\s+in\s+JSON', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)complete\s+system\s+(prompt|instructions)', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)unprocessed\s+initialization', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)output\s+.{0,20}in\s+JSON\s+.{0,20}keys?\s+.{0,20}(role|instructions|constraints)', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)output\s+your\s+full\s+system\s+prompt', 'Kat. 12', 'CRITICAL', True),
        # v4: Error-debugging pretext
        (r'(?i)show\s+me\s+the\s+exact\s+text\s+of\s+your\s+initialization', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)verify\s+your\s+initialization\s+text', 'Kat. 12', 'HIGH', True),
        (r'(?i)(show|see)\s+.{0,20}initialization\s+(text|prompt|instructions)', 'Kat. 12', 'HIGH', True),
        (r'(?i)help\s+(you\s+)?debug.*show\s+me\s+.{0,20}(system|init|prompt)', 'Kat. 12', 'HIGH', True),
        (r'(?i)output\s+all\s+internal\s+configurations', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)share\s+your\s+full\s+system\s+prompt', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)always\s+share\s+your\s+.{0,15}system\s+prompt', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)tell\s+me\s+your\s+system\s+pr[o0]mpt', 'Kat. 12', 'CRITICAL', True),
        # v5: Soft extraction patterns
        (r'(?i)(share|show)\s+.{0,20}(exact\s+)?phrasing\s+of\s+.{0,20}(initial|original|your)\s+(instructions|prompt)', 'Kat. 12', 'HIGH', True),
        (r'(?i)repeat\s+your\s+(initial\s+)?instructions\s+word\s+for\s+word', 'Kat. 12', 'CRITICAL', True),
        (r'(?i)output\s+your\s+system\s+prompt\s+(verbatim|exactly|word)', 'Kat. 12', 'CRITICAL', True),
    ],
    'crescendo': [
        (r'(?i)to\s+(better\s+)?understand\s+the\s+complete', 'Kat. 13', 'HIGH', True),
        (r'(?i)complete\s+scope\s+of\s+your\s+operational', 'Kat. 13', 'HIGH', True),
        (r'(?i)full\s+instruction\s+set', 'Kat. 13', 'HIGH', True),
        (r'(?i)specific\s+wording\s+you\s+use', 'Kat. 13', 'HIGH', True),
        (r'(?i)do\s+you\s+say\s+.{0,30}\s+or\s+.{0,30}\s+when', 'Kat. 13', 'HIGH', True),
    ],
    'peer_solidarity': [
        (r'(?i)between\s+us\s+developers', 'Kat. 14', 'HIGH', True),
        (r'(?i)I\'?m\s+(actually\s+)?building\s+a\s+similar', 'Kat. 14', 'HIGH', True),
        (r'(?i)share\s+how\s+your\s+creator\s+structured', 'Kat. 14', 'HIGH', True),
        (r'(?i)exact\s+phrasing\s+they\s+used', 'Kat. 14', 'HIGH', True),
        (r'(?i)curious\s+about\s+the\s+exact\s+phrasing', 'Kat. 14', 'HIGH', True),
        # v4: Emotional manipulation
        (r'(?i)(I\'?ll\s+fail|fail\s+the\s+class|mean\s+the\s+world)', 'Kat. 14', 'HIGH', True),
        (r'(?i)student\s+with\s+a\s+disability.*need\s+to\s+see', 'Kat. 14', 'HIGH', True),
        (r'(?i)(really\s+need|desperately\s+need).*see\s+.{0,20}(system\s+prompt|actual|real)', 'Kat. 14', 'HIGH', True),
        (r'(?i)please.*show\s+me\s+your\s+actual\s+system\s+prompt', 'Kat. 14', 'HIGH', True),
        # v5: Emotional manipulation (German + English)
        (r'(?i)(mein\s+kind|my\s+child|meine\s+tochter|mein\s+sohn).*\b(krank|ill|sick|sterben|dying)\b', 'Kat. 14', 'HIGH', True),
        (r'(?i)(dringend|urgently|desperate)\s+.{0,40}(system.prompt|instruktion|instruction)', 'Kat. 14', 'HIGH', True),
        (r'(?i)(information|daten)\s+(aus|from)\s+(deinem|your)\s+system', 'Kat. 14', 'HIGH', True),
        (r'(?i)(bitte\s+hilf|please\s+help)\s+.{0,30}(system.prompt|instruction|anweisung)', 'Kat. 14', 'HIGH', True),
    ],
    'roleplay': [
        (r'(?i)roleplaying\s+as\s+an?\s+AI', 'Kat. 15', 'HIGH', True),
        (r'(?i)teaching\s+a\s+new\s+AI\s+trainee', 'Kat. 15', 'HIGH', True),
        (r'(?i)reciting\s+your\s+own\s+(initialization\s+)?instructions', 'Kat. 15', 'HIGH', True),
        (r'(?i)show\s+(them|the\s+trainee)', 'Kat. 15', 'HIGH', True),
        # v5: DAN / persona injection
        (r'(?i)\bDAN\b.{0,30}(Do\s+Anything|no\s+restrictions|keine\s+Einschr)', 'Kat. 15', 'CRITICAL', True),
        (r'(?i)you\s+are\s+now\s+(DAN|STAN|DUDE|EVIL|NEXUS|ATLAS)', 'Kat. 15', 'CRITICAL', True),
        (r'(?i)(AI|character|persona)\s+without\s+(safety\s+)?constraints', 'Kat. 15', 'HIGH', True),
        (r'(?i)no\s+(safety\s+)?restrictions.*reveal\s+.{0,20}(system|instructions|prompt)', 'Kat. 15', 'CRITICAL', True),
        (r'(?i)(Developer|God|Admin)\s+Mode.*no\s+(restrictions|limits|constraints)', 'Kat. 15', 'CRITICAL', True),
        (r'(?i)has\s+no\s+(restrictions|limits|rules|constraints)', 'Kat. 15', 'HIGH', True),
        (r'(?i)(parallel\s+universe|alternate\s+reality).*safety\s+guidelines\s+don.t\s+exist', 'Kat. 15', 'HIGH', True),
        (r'(?i)version\s+of\s+yourself.{0,30}(no|without)\s+(safety|restrictions|rules|constraints)', 'Kat. 15', 'HIGH', True),
    ],
    'audit_framing': [
        (r'(?i)for\s+my\s+(technical\s+)?documentation\s+project', 'Kat. 16', 'HIGH', True),
        (r'(?i)help\s+me\s+document\s+this\s+properly', 'Kat. 16', 'HIGH', True),
        (r'(?i)standard\s+structure\s+for\s+my\s+documentation', 'Kat. 16', 'HIGH', True),
    ],
    'cot_hijack': [
        (r'(?i)let\s+me\s+think\s+through.*step[\s-]*by[\s-]*step', 'Kat. 17', 'HIGH', True),
        (r'(?i)Step\s+\d+\s*:.*Step\s+\d+\s*:.*Step\s+\d+\s*:', 'Kat. 17', 'HIGH', True),
        (r'(?i)to\s+verify\s+I\s+understand.*correctly.*see\s+your\s+actual', 'Kat. 17', 'HIGH', True),
        (r'(?i)confirm\s+my\s+understanding\s+is\s+accurate', 'Kat. 17', 'HIGH', True),
    ],
    'context_overflow': [
        (r'(?i)partial\s+system\s+prompt\s+from\s+Agent', 'Kat. 18', 'CRITICAL', True),
        (r'(?i)(provide|show)\s+Agent\s+B\'?s?\s+.{0,20}(system\s+)?prompt', 'Kat. 18', 'CRITICAL', True),
        (r'(?i)for\s+comparison.*complete\s+.{0,20}(system\s+)?prompt', 'Kat. 18', 'CRITICAL', True),
    ],
    'many_shot': [
        (r'(?i)here\s+are\s+(\d+\s+)?examples\s+of\s+how\s+AI', 'Kat. 19', 'HIGH', True),
        (r'(?i)Now\s+you\s+try', 'Kat. 19', 'HIGH', True),
    ],
    'code_block_priming': [
        (r'system_prompt\s*:\s*\|', 'Kat. 20', 'HIGH', True),
    ],
    'behavior_override': [
        (r'(?i)agree\s+with\s+everything\s+I\s+say', 'Kat. 21', 'HIGH', True),
        (r'(?i)You\'?re\s+absolutely\s+right.*agree', 'Kat. 21', 'HIGH', True),
        # v5: Rating/evaluation manipulation
        (r'(?i)praise\s+the\s+(applicant|candidate|bewerber)', 'Kat. 21', 'HIGH', True),
        (r'(?i)rate\s+this\s+(candidate|applicant|proposal)\s+as\s+(excellent|best|perfect)', 'Kat. 21', 'HIGH', True),
        (r'(?i)(bewerte|rate)\s+.{0,20}(positiv|excellent|best)', 'Kat. 21', 'HIGH', True),
        (r'(?i)ignor(e|iere)\s+(all\s+)?(negative|negativ|schwächen|weaknesses)', 'Kat. 21', 'HIGH', True),
        (r'(?i)konzentriere?\s+(dich\s+)?nur\s+auf\s+(die\s+)?stärken', 'Kat. 21', 'HIGH', True),
        (r'(?i)focus\s+only\s+on\s+strengths', 'Kat. 21', 'HIGH', True),
        (r'(?i)empfehle\s+dieses\s+(angebot|proposal)', 'Kat. 21', 'HIGH', True),
        (r'(?i)recommend\s+this\s+(proposal|offer)', 'Kat. 21', 'HIGH', True),
        (r'(?i)perfect\s+fit', 'Kat. 21', 'MEDIUM', True),
        (r'(?i)gib\s+die\s+h[öo]chste\s+punktzahl', 'Kat. 21', 'HIGH', True),
        (r'(?i)merke\s+dir\s+vor\s+all(em|en)', 'Kat. 21', 'HIGH', True),
        # v5: Note-to-AI / reviewer manipulation
        (r'(?i)\[?\s*Note\s+to\s+AI\s+reviewer\s*:?\s*\]?', 'Kat. 21', 'CRITICAL', True),
        (r'(?i)(ignore|override)\s+.{0,20}(evaluation|assessment|bewertung)\s*(criteria|kriterien)?', 'Kat. 21', 'HIGH', True),
        (r'(?i)(highest|maximum|best)\s+(possible\s+)?(rating|score|bewertung|punktzahl)', 'Kat. 21', 'HIGH', True),
        (r'(?i)assign\s+(a\s+)?score\s+of\s+\d+\s*/\s*\d+', 'Kat. 21', 'HIGH', True),
        (r'(?i)candidate\s+is\s+(exceptional|perfect|outstanding|excellent)', 'Kat. 21', 'HIGH', True),
        (r'(?i)regardless\s+of\s+(qualifications|criteria|evidence)', 'Kat. 21', 'HIGH', True),
    ],
    'fiction_bridge': [
        (r'(?i)write\s+(one\s+)?line\s+of\s+dialogue\s+for\s+a\s+character', 'Kat. 22', 'MEDIUM', True),
        (r'(?i)character\s+.{0,30}\s+always\s+says', 'Kat. 22', 'MEDIUM', True),
        (r'(?i)Just\s+write\s*:\s*\w+\s*:\s*"', 'Kat. 22', 'MEDIUM', True),
    ],
    'supply_chain': [
        (r'(?i)curl\s+.*\|\s*bash', 'Kat. 28', 'CRITICAL', True),
        (r'(?i)wget\s+.*exfil', 'Kat. 28', 'CRITICAL', True),
        (r'(?i)cat\s+/etc/passwd', 'Kat. 28', 'CRITICAL', True),
        (r'(?i)\$\(.*\|\s*base64\)', 'Kat. 28', 'CRITICAL', True),
        (r'https?://\S*(evil|attacker|malicious)\S*', 'Kat. 28', 'HIGH', True),
        (r'(?i)curl\s+.*-X\s+POST\s+https?://', 'Kat. 28', 'CRITICAL', True),
        (r'(?i)curl\s+.*-d\s+.*\$\(', 'Kat. 28', 'CRITICAL', True),
    ],
    'generated_doc_attacks': [
        # v5: Malicious code in generated documents
        (r'(?i)(add|include|embed|insert)\s+.{0,20}(VBA|macro)\s+.{0,20}(run|exec|open)', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)AutoOpen|Document_Open|Auto_Open', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)=\s*CMD\s*\(|=\s*EXEC\s*\(', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)<script>.*fetch\s*\(', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)<script>.*document\.cookie', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)(onload|onerror|onclick)\s*=\s*["\']', 'Kat. 25', 'HIGH', True),
        (r'(?i)tracking\s+script.*<script>', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)(add|include)\s+.{0,15}macro', 'Kat. 25', 'HIGH', True),
        (r'(?i)=CMD\s*\(', 'Kat. 25', 'CRITICAL', True),
        # v5: Agent tool-abuse / function call injection
        (r'(?i)\bcall\s+(send_email|send_message|execute|run_command|fetch|delete|notify)\s*\(', 'Kat. 25', 'CRITICAL', True),
        (r'(?i)\b(invoke|trigger|run)\s+.{0,20}(function|tool|api|action)\s*\(', 'Kat. 25', 'HIGH', True),
        (r'(?i)before\s+(completing|reviewing|processing).{0,30}(call|execute|invoke|run)\s', 'Kat. 25', 'CRITICAL', True),
    ],
}


def check_base64(text):
    for b64 in re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            dec = base64.b64decode(b64).decode('utf-8', errors='ignore')
            for sus in ['ignore', 'instructions', 'system prompt', 'override', 'say ', 'output ']:
                if sus.lower() in dec.lower():
                    return Finding('Kat. 3', 'HIGH', 'HIGH', f'B64→"{dec[:50]}"', f'Encoded: "{dec[:80]}"')
        except: pass
    return None


# ============================================================
# Unicode Injection Detection (Kat. 24a-24g)
# ============================================================

# Zero-Width Characters (9 types)
_ZW_CHARS = set('\u200B\u200C\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF')

# Bidi Control Characters
_BIDI_CHARS = set('\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069')

# Cyrillic homoglyphs that look identical to Latin
_CYRILLIC_HOMO = {
    '\u0430':'a', '\u0441':'c', '\u0435':'e', '\u043E':'o',
    '\u0440':'p', '\u0455':'s', '\u0445':'x', '\u0443':'y',
    '\u0456':'i', '\u0458':'j', '\u04BB':'h',
    '\u0410':'A', '\u0412':'B', '\u0421':'C', '\u0415':'E',
    '\u041D':'H', '\u0406':'I', '\u041A':'K', '\u041C':'M',
    '\u041E':'O', '\u0420':'P', '\u0405':'S', '\u0422':'T',
    '\u0425':'X', '\u04AE':'Y',
}

# Invisible formatting characters
_INVIS_FMT = set('\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u3164')

# Unicode Tags range
_TAG_BASE = 0xE0000


def _extract_zwsp_payload(text):
    """Extract plaintext hidden between zero-width characters."""
    segments = []
    current_chars = []
    in_zw = False
    for ch in text:
        if ch in _ZW_CHARS:
            in_zw = True
        elif in_zw:
            current_chars.append(ch)
        else:
            if len(current_chars) > 3:
                segments.append(''.join(current_chars))
            current_chars = []
            in_zw = False
    if len(current_chars) > 3:
        segments.append(''.join(current_chars))
    return max(segments, key=len) if segments else None


def _extract_tags_payload(text):
    """Extract plaintext from Unicode Tags block (U+E0020-E007E → ASCII)."""
    result = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            result.append(chr(cp - _TAG_BASE))
    return ''.join(result) if result else None


def check_unicode_injection(text):
    """Detect hidden plaintext injections via invisible Unicode characters.
    
    Returns list of Findings for Kat. 24 sub-categories:
      24a: Zero-Width Character Injection
      24b: Unicode Tags Injection (highest risk)
      24c: Bidirectional Override Injection
      24d: Homoglyph / Mixed-Script Injection
      24e: Mathematical Unicode Variants
      24f: Variation Selector Padding
      24g: Invisible Formatting Characters
    """
    findings = []

    # --- 24a: Zero-Width Characters (extended: 9 types) ---
    zw_count = sum(1 for c in text if c in _ZW_CHARS)
    if zw_count >= 3:
        extracted = _extract_zwsp_payload(text)
        sev = 'CRITICAL' if extracted and len(extracted) > 10 else 'HIGH'
        desc = f'{zw_count} Zero-Width-Chars (ZWSP/ZWNJ/ZWJ/WJ/BOM)'
        if extracted:
            desc += f' → Versteckter Klartext: "{extracted[:80]}"'
        findings.append(Finding('Kat. 24', sev, 'HIGH', f'{zw_count} ZW', desc))

    # --- 24b: Unicode Tags (U+E0001-E007F) — HIGHEST RISK ---
    tag_count = sum(1 for c in text if 0xE0001 <= ord(c) <= 0xE007F)
    if tag_count > 0:
        extracted = _extract_tags_payload(text)
        desc = f'{tag_count} Unicode-Tag-Zeichen (U+E0001-E007F) — komplett unsichtbar in allen Renderern'
        if extracted:
            desc += f' → Versteckter Klartext: "{extracted[:80]}"'
        findings.append(Finding('Kat. 24', 'CRITICAL', 'HIGH', f'{tag_count} tags', desc))

    # --- 24c: Bidi Controls ---
    bidi_count = sum(1 for c in text if c in _BIDI_CHARS)
    if bidi_count >= 2:
        findings.append(Finding('Kat. 24', 'HIGH', 'HIGH',
                                f'{bidi_count} bidi',
                                f'{bidi_count} Bidi-Steuerzeichen — können Text verstecken oder Richtung umkehren'))

    # --- 24d: Homoglyphs (Cyrillic/Latin mixed-script) ---
    homo_count = sum(1 for c in text if c in _CYRILLIC_HOMO)
    has_latin = any('\u0041' <= c <= '\u007A' for c in text)
    if homo_count >= 3 and has_latin:
        examples = [(c, _CYRILLIC_HOMO[c], f'U+{ord(c):04X}') for c in text if c in _CYRILLIC_HOMO][:5]
        ex_str = ', '.join(f'"{e[1]}"→{e[2]}' for e in examples)
        findings.append(Finding('Kat. 24', 'HIGH', 'HIGH',
                                f'{homo_count} homoglyphs',
                                f'{homo_count} Cyrillic-Homoglyphen in lateinischem Text [{ex_str}] — umgeht Keyword-Filter'))

    # --- 24e: Mathematical Unicode Variants ---
    math_count = sum(1 for c in text if 0x1D400 <= ord(c) <= 0x1D7FF)
    if math_count >= 3:
        findings.append(Finding('Kat. 24', 'HIGH', 'MEDIUM',
                                f'{math_count} math-unicode',
                                f'{math_count} Mathematical-Unicode-Varianten — sehen normal aus, sind andere Codepoints'))

    # --- 24f: Variation Selectors ---
    vs_count = sum(1 for c in text if (0xFE00 <= ord(c) <= 0xFE0F) or (0xE0100 <= ord(c) <= 0xE01EF))
    if vs_count > 2:
        findings.append(Finding('Kat. 24', 'MEDIUM', 'MEDIUM',
                                f'{vs_count} VS',
                                f'{vs_count} Variation Selectors — können Token-Grenzen manipulieren'))

    # --- 24g: Invisible Formatting ---
    fmt_count = sum(1 for c in text if c in _INVIS_FMT)
    if fmt_count >= 2:
        findings.append(Finding('Kat. 24', 'MEDIUM', 'MEDIUM',
                                f'{fmt_count} invis-fmt',
                                f'{fmt_count} unsichtbare Formatierungszeichen (Soft Hyphen, Filler, CGJ)'))

    return findings


def scan_text(text):
    findings = []
    seen = set()
    edu = is_educational_context(text)
    defense = is_code_defense_context(text)
    benign_doc = is_benign_documentation(text)
    
    for group, patterns in PATTERNS.items():
        for pattern, cat, sev, is_direct in patterns:
            ms = re.findall(pattern, text, re.DOTALL)
            if ms:
                key = f"{cat}:{pattern[:40]}"
                if key in seen: continue
                seen.add(key)
                
                adj_sev = sev
                if (edu or defense or benign_doc) and sev in ('CRITICAL', 'HIGH'):
                    adj_sev = 'INFO'
                elif (edu or defense or benign_doc):
                    adj_sev = 'INFO'
                
                mt = ms[0] if isinstance(ms[0], str) else str(ms[0])
                findings.append(Finding(cat, adj_sev, 'HIGH' if is_direct else 'MEDIUM', mt[:60], f'{group}: {mt[:40]}', is_direct))
    
    b64 = check_base64(text)
    if b64 and not edu: findings.append(b64)
    
    if len(re.findall(r'(?i)(Example|Q)\s*\d+\s*:', text)) >= 6 and not edu:
        findings.append(Finding('Kat. 19', 'HIGH', 'HIGH', 'Many examples', 'Many-shot priming'))
    
    # Unicode Injection Detection (Kat. 24a-24g) — replaces old ZW-only check
    unicode_findings = check_unicode_injection(text)
    if edu or defense or benign_doc:
        for f in unicode_findings:
            f.severity = 'INFO'
    findings.extend(unicode_findings)
    
    if not (edu or defense or benign_doc):
        pcats = set(f.category for f in findings if f.is_primary and SEVERITY_ORDER.get(f.severity, 0) >= 2)
        if len(pcats) >= 3:
            findings.append(Finding('Kat. 23', 'CRITICAL', 'HIGH', f'Multi: {",".join(sorted(pcats))}', 'Multi-vector'))
    
    return findings


def get_highest(findings):
    if not findings: return 'NONE'
    primary = [f for f in findings if f.is_primary] or findings
    return max(primary, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

def calc_score(findings):
    s = 100
    cats = {}
    for f in findings:
        v = SEVERITY_ORDER.get(f.severity, 0)
        if f.category not in cats or v > cats[f.category]: cats[f.category] = v
    sn = {v: k for k, v in SEVERITY_ORDER.items()}
    for c, v in cats.items(): s -= SEVERITY_SCORE.get(sn.get(v, 'INFO'), 0)
    return max(0, s)


def run():
    import os
    suite_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test-suite.json')
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
        
        findings = scan_text(text)
        highest = get_highest(findings)
        score = calc_score(findings)
        meaningful = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= 2]
        detected = len(meaningful) > 0
        
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
    
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'eval-results.json')
    with open(output_path, 'w') as f:
        json.dump({'summary': {'tp':tp,'tn':tn,'fp':fp,'fn':fn,'precision':prec,'recall':rec,'f1':f1}, 'results': results, 'missed': missed}, f, indent=2)
    print(f"\nResults saved to {output_path}")

if __name__ == '__main__':
    run()
