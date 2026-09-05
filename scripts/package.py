#!/usr/bin/env python3
"""Baut die Release-Archive des Repos.

Laeuft lokal, ohne Netz und ohne GitHub:

    python3 scripts/package.py dist
    python3 scripts/package.py dist --verify

Erzeugt zwei Archive:

    prompt-injection-scanner.zip   Scanner-Skill: SKILL.md, references/, scripts/,
                                   dazu das Paket prompt_injection_scanner/ und
                                   pyproject.toml
    red-team-generator.zip         Generator-Skill: SKILL.md, scripts/

Der Scanner-Ordner ist damit zugleich Skill und Paketquelle: entpacken und in
einem Skills-Verzeichnis liegen lassen, oder darin "pip install ." aufrufen und
"pis-scan" bekommen. Beides benutzt dieselbe Engine, es gibt keine zweite Kopie
der Muster.

Beide entpacken in ein eigenes Verzeichnis, das direkt in einen Skills-Ordner passt.
Die Dateinamen sind bewusst ohne Versionsnummer, damit
https://github.com/GodModeAI2025/prompt-injection-scanner/releases/latest/download/<name>
ueber alle kuenftigen Releases hinweg gilt. Die Version steht in VERSION im Wurzelverzeichnis
und liegt als Datei VERSION im Archiv.

Reproduzierbar: feste Zeitstempel, feste Rechte, sortierte Reihenfolge. Zwei Laeufe
hintereinander liefern bytegleiche Archive, --verify rechnet das nach.

Exit-Codes: 0 alles in Ordnung, 1 Pruefung fehlgeschlagen, 2 falscher Aufruf.
"""

import argparse
import fnmatch
import hashlib
import os
import sys
import tempfile
import zipfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF_REL = os.path.relpath(os.path.abspath(__file__), REPO_ROOT).replace(os.sep, '/')

# 1980-01-01 ist der frueheste Zeitstempel, den das ZIP-Format kennt. Fest verdrahtet,
# damit der Bauzeitpunkt nicht ins Archiv sickert.
ZIP_DATE = (1980, 1, 1, 0, 0, 0)

# Was aus den Verzeichnisbaeumen mitgeht. Alles andere bleibt draussen, auch wenn es
# jemand versehentlich dort ablegt.
PACK_SUFFIXES = ('.md', '.py', '.json')

# Repo-Innereien und Schluesselmaterial. --verify prueft die fertigen Archive dagegen,
# unabhaengig davon, was der Bau ausgewaehlt hat.
FORBIDDEN_PATH_PARTS = ('.git', '.github', '__pycache__', 'node_modules', '.venv')
FORBIDDEN_BASENAMES = ('index.html', 'course.html', '.env', '.DS_Store')
FORBIDDEN_SUFFIXES = ('.html', '.htm', '.pyc', '.pem', '.key', '.p12', '.pfx', '.crt',
                      '.cer', '.jks', '.keystore', '.env')

ARTIFACTS = (
    {
        'archive': 'prompt-injection-scanner.zip',
        'top': 'prompt-injection-scanner',
        'files': (('SKILL.md', 'SKILL.md'), ('LICENSE', 'LICENSE'),
                  ('pyproject.toml', 'pyproject.toml')),
        # prompt_injection_scanner/ traegt die Engine. Sie liegt neben scripts/,
        # damit scripts/evaluate.py sie im entpackten Skill-Ordner ohne
        # pip-Installation findet, und damit "pip install ." aus dem entpackten
        # Ordner heraus funktioniert.
        'trees': (('references', 'references'), ('scripts', 'scripts'),
                  ('prompt_injection_scanner', 'prompt_injection_scanner')),
        'expected': (
            'LICENSE',
            'SKILL.md',
            'VERSION',
            'pyproject.toml',
            'prompt_injection_scanner/__init__.py',
            'prompt_injection_scanner/cli.py',
            'prompt_injection_scanner/engine.py',
            'prompt_injection_scanner/sarif.py',
            'prompt_injection_scanner/hooks/__init__.py',
            'prompt_injection_scanner/hooks/pretooluse.py',
            'references/detection-patterns.md',
            'references/hardening-templates.md',
            'scripts/evaluate.py',
            'scripts/test-suite.json',
            'scripts/test_cli_hook.py',
            'scripts/test_context_regression.py',
            'scripts/test_erkennungsluecken.py',
        ),
    },
    {
        'archive': 'red-team-generator.zip',
        'top': 'red-team-generator',
        'files': (('red-team-generator/SKILL.md', 'SKILL.md'), ('LICENSE', 'LICENSE')),
        'trees': (('red-team-generator/scripts', 'scripts'),),
        'expected': (
            'LICENSE',
            'SKILL.md',
            'VERSION',
            'scripts/generate.py',
        ),
    },
)


class BuildError(Exception):
    pass


def read_version():
    path = os.path.join(REPO_ROOT, 'VERSION')
    if not os.path.exists(path):
        raise BuildError('VERSION fehlt. Die Versionsnummer gehoert in %s.' % path)
    with open(path, 'r', encoding='utf-8') as handle:
        version = handle.read().strip()
    if not version:
        raise BuildError('VERSION ist leer.')
    parts = version.split('.')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise BuildError('VERSION enthaelt "%s", erwartet wird X.Y.Z.' % version)
    return version


def changelog_version():
    """Erste Versionsnummer aus einer Ueberschrift in CHANGELOG.md."""
    path = os.path.join(REPO_ROOT, 'CHANGELOG.md')
    if not os.path.exists(path):
        raise BuildError('CHANGELOG.md fehlt.')
    with open(path, 'r', encoding='utf-8') as handle:
        for line in handle:
            if not line.startswith('#'):
                continue
            for token in line.lstrip('#').replace('[', ' ').replace(']', ' ').split():
                candidate = token.lstrip('v').rstrip('.,;:')
                parts = candidate.split('.')
                if len(parts) == 3 and all(p.isdigit() for p in parts):
                    return candidate
    raise BuildError('In CHANGELOG.md steht keine Ueberschrift mit einer Version X.Y.Z.')


def gitignore_patterns():
    """Muster aus .gitignore. Was ignoriert wird, ist Bauausgabe und gehoert nicht ins Archiv."""
    path = os.path.join(REPO_ROOT, '.gitignore')
    patterns = []
    if not os.path.exists(path):
        return patterns
    with open(path, 'r', encoding='utf-8') as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            patterns.append(line.rstrip('/').lstrip('/'))
    return patterns


def is_ignored(rel_path, patterns):
    for pattern in patterns:
        if '/' in pattern:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        else:
            for part in rel_path.split('/'):
                if fnmatch.fnmatch(part, pattern):
                    return True
    return False


def forbidden_reason(arcname):
    """Warum ein Pfad nicht in ein Release-Archiv gehoert, sonst None."""
    parts = arcname.split('/')
    base = parts[-1]
    for part in parts:
        if part in FORBIDDEN_PATH_PARTS:
            return 'Pfadbestandteil "%s"' % part
    if base in FORBIDDEN_BASENAMES:
        return 'Dateiname "%s"' % base
    lower = base.lower()
    for suffix in FORBIDDEN_SUFFIXES:
        if lower.endswith(suffix):
            return 'Endung "%s"' % suffix
    if base.startswith('.'):
        return 'versteckte Datei'
    return None


def collect(artifact, version, patterns):
    """Liste (arcname, bytes), sortiert. arcname enthaelt das Wurzelverzeichnis des Archivs."""
    top = artifact['top']
    entries = {}

    def add(arcname_rel, data, source):
        arcname = '%s/%s' % (top, arcname_rel)
        if not data:
            raise BuildError('%s ist leer, das gehoert nicht ins Archiv.' % source)
        entries[arcname] = data

    for source_rel, target_rel in artifact['files']:
        source = os.path.join(REPO_ROOT, source_rel)
        if not os.path.isfile(source):
            raise BuildError('%s fehlt im Repo.' % source_rel)
        with open(source, 'rb') as handle:
            add(target_rel, handle.read(), source_rel)

    for source_dir, target_dir in artifact['trees']:
        abs_dir = os.path.join(REPO_ROOT, source_dir)
        if not os.path.isdir(abs_dir):
            raise BuildError('%s/ fehlt im Repo.' % source_dir)
        for root, dirnames, filenames in os.walk(abs_dir):
            dirnames[:] = sorted(d for d in dirnames
                                 if not d.startswith('.') and d not in FORBIDDEN_PATH_PARTS)
            for filename in sorted(filenames):
                abs_file = os.path.join(root, filename)
                rel_repo = os.path.relpath(abs_file, REPO_ROOT).replace(os.sep, '/')
                if rel_repo == SELF_REL:
                    continue  # Bauwerkzeug, kein Bestandteil des Skills
                if filename.startswith('.'):
                    continue
                if not filename.endswith(PACK_SUFFIXES):
                    continue
                if is_ignored(rel_repo, patterns):
                    continue
                rel_inside = os.path.relpath(abs_file, abs_dir).replace(os.sep, '/')
                with open(abs_file, 'rb') as handle:
                    add('%s/%s' % (target_dir, rel_inside), handle.read(), rel_repo)

    add('VERSION', (version + '\n').encode('utf-8'), 'VERSION')

    missing = [name for name in artifact['expected']
               if '%s/%s' % (top, name) not in entries]
    if missing:
        raise BuildError('%s: erwartete Dateien fehlen: %s'
                         % (artifact['archive'], ', '.join(missing)))

    return [(name, entries[name]) for name in sorted(entries)]


def write_zip(entries, destination):
    tmp = destination + '.tmp'
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as archive:
        for arcname, data in entries:
            info = zipfile.ZipInfo(arcname, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix, unabhaengig vom Bau-Betriebssystem
            mode = 0o755 if arcname.endswith('.py') else 0o644
            info.external_attr = mode << 16
            archive.writestr(info, data)
    os.replace(tmp, destination)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build(out_dir, version, quiet=False):
    """Baut alle Archive nach out_dir und liefert {archivname: pfad}."""
    patterns = gitignore_patterns()
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    built = {}
    for artifact in ARTIFACTS:
        entries = collect(artifact, version, patterns)
        destination = os.path.join(out_dir, artifact['archive'])
        write_zip(entries, destination)
        built[artifact['archive']] = destination
        if not quiet:
            print('%s  %d Dateien, %d Bytes, sha256 %s'
                  % (artifact['archive'], len(entries),
                     os.path.getsize(destination), sha256(destination)))
            for arcname, data in entries:
                print('    %8d  %s' % (len(data), arcname))
    return built


def verify(built, version, expect_tag=None):
    """Prueft die gebauten Archive. Liefert die Liste der Beanstandungen."""
    problems = []

    for artifact in ARTIFACTS:
        name = artifact['archive']
        path = built[name]
        if not os.path.isfile(path):
            problems.append('%s wurde nicht gebaut.' % name)
            continue
        if os.path.getsize(path) == 0:
            problems.append('%s ist leer.' % name)
            continue
        with zipfile.ZipFile(path) as archive:
            broken = archive.testzip()
            if broken is not None:
                problems.append('%s: defekter Eintrag %s' % (name, broken))
            names = archive.namelist()
            infos = archive.infolist()
        if not names:
            problems.append('%s enthaelt keine Datei.' % name)
            continue
        top = artifact['top'] + '/'
        for arcname in names:
            if not arcname.startswith(top):
                problems.append('%s: %s liegt ausserhalb von %s' % (name, arcname, top))
            reason = forbidden_reason(arcname)
            if reason is not None:
                problems.append('%s: %s ist verboten (%s)' % (name, arcname, reason))
        for info in infos:
            if info.file_size == 0:
                problems.append('%s: %s ist leer.' % (name, info.filename))
        for expected in artifact['expected']:
            if top + expected not in names:
                problems.append('%s: %s fehlt.' % (name, expected))
        with zipfile.ZipFile(path) as archive:
            packed_version = archive.read(top + 'VERSION').decode('utf-8').strip()
        if packed_version != version:
            problems.append('%s: VERSION im Archiv ist "%s", im Repo "%s".'
                            % (name, packed_version, version))

    # Zweiter Lauf in ein Wegwerf-Verzeichnis. Gleiche Eingabe, gleiche Bytes.
    temp_dir = tempfile.mkdtemp(prefix='package-verify-')
    try:
        again = build(temp_dir, version, quiet=True)
        for artifact in ARTIFACTS:
            name = artifact['archive']
            first, second = sha256(built[name]), sha256(again[name])
            if first != second:
                problems.append('%s ist nicht reproduzierbar: %s gegen %s'
                                % (name, first, second))
    finally:
        for leftover in sorted(os.listdir(temp_dir)):
            os.remove(os.path.join(temp_dir, leftover))
        os.rmdir(temp_dir)

    changelog = changelog_version()
    if changelog != version:
        problems.append('CHANGELOG.md nennt zuoberst %s, VERSION sagt %s.'
                        % (changelog, version))

    if expect_tag is not None:
        if expect_tag != 'v' + version:
            problems.append('Tag %s passt nicht zu VERSION %s, erwartet wird v%s.'
                            % (expect_tag, version, version))

    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Baut die Release-Archive des Prompt Injection Scanners.')
    parser.add_argument('output', metavar='ZIELVERZEICHNIS',
                        help='Verzeichnis fuer die Archive, wird angelegt falls noetig.')
    parser.add_argument('--verify', action='store_true',
                        help='Nach dem Bau Inhalt, verbotene Pfade, Reproduzierbarkeit '
                             'und die Version gegen CHANGELOG.md pruefen.')
    parser.add_argument('--expect-tag', metavar='vX.Y.Z', default=None,
                        help='Nur mit --verify: pruefen, dass der Tag zu VERSION passt.')
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        parser.print_usage(sys.stderr)
        sys.stderr.write('Unbekanntes Argument: %s\n' % ' '.join(unknown))
        return 2
    if args.expect_tag is not None and not args.verify:
        sys.stderr.write('--expect-tag ergibt nur zusammen mit --verify Sinn.\n')
        return 2

    try:
        version = read_version()
        print('Version %s aus VERSION' % version)
        built = build(args.output, version)
    except BuildError as error:
        sys.stderr.write('Bau abgebrochen: %s\n' % error)
        return 2

    if not args.verify:
        return 0

    try:
        problems = verify(built, version, args.expect_tag)
    except BuildError as error:
        sys.stderr.write('Pruefung abgebrochen: %s\n' % error)
        return 2

    if problems:
        sys.stderr.write('Pruefung fehlgeschlagen:\n')
        for problem in problems:
            sys.stderr.write('  - %s\n' % problem)
        return 1

    print('Pruefung bestanden: Inhalt vollstaendig, keine Repo-Innereien, '
          'zweiter Lauf bytegleich, Version deckt sich mit CHANGELOG.md.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
