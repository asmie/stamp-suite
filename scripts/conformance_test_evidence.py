"""Static test-reference inventory, not a protocol or runtime coverage checker."""
import ast
from collections import Counter, defaultdict
import os
from pathlib import Path
import re

BACKTICK = re.compile(r'`([^`]+)`')
RUST_ITEM = re.compile(r'^([A-Za-z0-9_./-]+\.rs)::([A-Za-z_][A-Za-z0-9_:]*)$')
PY_ITEM = re.compile(r'^([A-Za-z0-9_./-]+\.py)::([A-Za-z_][A-Za-z0-9_:]*)$')
WIRE = re.compile(r'\bWire tests?\s*:\s*((?:`[A-Za-z0-9_./-]+\.py::[A-Za-z_][A-Za-z0-9_:]*`(?:\s*,\s*|\s+and\s+)?)+)', re.I)
NORMATIVE = re.compile(r'\b(?:MUST|SHALL|REQUIRED)\b')
RAW_STRING = re.compile(r'(?:br|r)(#*)"')
CHAR = re.compile(r"'(?:\\.|[^'\\\n])'")


def mask_rust(source):
    """Mask strings and nested comments, retaining offsets and newlines."""
    result = list(source)
    index = 0
    while index < len(source):
        end = None
        if source.startswith('//', index):
            end = source.find('\n', index)
            if end < 0:
                end = len(source)
        elif source.startswith('/*', index):
            end, depth = index + 2, 1
            while end < len(source) and depth:
                if source.startswith('/*', end):
                    depth += 1
                    end += 2
                elif source.startswith('*/', end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = RAW_STRING.match(source, index) if source[index] in 'br' else None
            if raw:
                closing = '"' + raw[1]
                stop = source.find(closing, raw.end())
                end = len(source) if stop < 0 else stop + len(closing)
            elif source[index] == '"':
                end = index + 1
                while end < len(source):
                    if source[end] == '\\':
                        end += 2
                    elif source[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
            elif source[index] == "'":
                char = CHAR.match(source, index)
                if char:
                    end = char.end()
        if end is None:
            index += 1
        else:
            for position in range(index, min(end, len(source))):
                if source[position] != '\n':
                    result[position] = ' '
            index = end
    return ''.join(result)


TOKEN = re.compile(r'\s+|#\s*\[|\bfn\s+([A-Za-z_]\w*)|[A-Za-z_]\w*|.', re.S)


def rust_functions(source):
    code, index, attributes, result = mask_rust(source), 0, [], []
    while index < len(code):
        token = TOKEN.match(code, index)
        value = token[0]
        index = token.end()
        if value.isspace():
            continue
        if re.fullmatch(r'#\s*\[', value):
            start, depth = index, 1
            while index < len(code) and depth:
                depth += (code[index] == '[') - (code[index] == ']')
                index += 1
            attributes.append(code[start:index - 1].strip())
        elif value in ('pub', 'async', 'unsafe', 'extern'):
            if value == 'pub':
                qualifier = re.match(r'\s*\([^)]*\)', code[index:])
                if qualifier:
                    index += qualifier.end()
        elif token[1]:
            is_test = any(re.match(r'^(?:[A-Za-z_]\w*::)*test(?:\s|\(|$)', a) for a in attributes)
            result.append(dict(item=token[1], line=source.count('\n', 0, token.start()) + 1,
                               is_test=is_test, ignored=any(re.match(r'^ignore\b', a) for a in attributes)))
            attributes = []
        else:
            attributes = []
    return result


def dedicated_test_file(path):
    p = Path(path)
    return ((p.parts[0] == 'tests' and 'common' not in p.parts)
            or p.name == 'tests.rs' or p.name.endswith('_tests.rs')
            or 'tests' in p.parts[1:-1])


class TestIndex:
    def __init__(self, root, paths, resolve, scope):
        self.root, self.resolve, self.scope = Path(root).resolve(), resolve, scope
        self.by_name, self.by_file, self.functions = defaultdict(list), defaultdict(list), {}
        self.non_tests = set()
        for path in sorted(paths):
            declarations = rust_functions((self.root / path).read_text(encoding='utf-8'))
            self.functions[path] = declarations
            for item in declarations:
                if not item['is_test']:
                    self.non_tests.add(item['item'])
                if item['is_test']:
                    reference = dict(kind='rust-test', path=path, item=item['item'],
                                     line=item['line'], ignored=item['ignored'])
                    self.by_name[item['item']].append(reference)
                    self.by_file[path].append(reference)
        self.python = {}
        self.python_files = None

    def resolve_python(self, cite):
        if (self.root / cite).is_file():
            return cite
        if self.python_files is None:
            self.python_files = []
            for base in ('scripts', 'tests', 'examples', 'fuzz'):
                for directory, dirs, files in os.walk(self.root / base):
                    dirs[:] = [d for d in dirs if d not in ('target', '__pycache__', '.git')]
                    self.python_files.extend((Path(directory) / f).relative_to(self.root).as_posix()
                                             for f in files if f.endswith('.py'))
        candidates = [p for p in self.python_files if p.endswith('/' + cite)]
        return candidates[0] if len(candidates) == 1 else None

    def rust_item(self, path, item):
        files = self.scope(path)
        name = item.split('::')[-1]
        if name == 'tests':
            code = mask_rust((self.root / path).read_text(encoding='utf-8'))
            if re.search(r'\bmod\s+tests\b', code):
                tests = [t for f in files for t in self.by_file[f]]
                if tests:
                    return [dict(kind='rust-test-module', path=path, item=item,
                                 test_count=len(tests), ignored_test_count=sum(t['ignored'] for t in tests))]
            return []
        # A helper in the cited file is not a same-named test in a child file.
        declarations = [d for d in self.functions.get(path, []) if d['item'] == name]
        if declarations and not any(d['is_test'] for d in declarations) and 'tests' not in item.split('::'):
            return []
        return [t for t in self.by_name[name] if t['path'] in files]

    def python_items(self, path):
        path = self.resolve_python(path)
        if path is None:
            raise OSError('unresolved or ambiguous Python source')
        if path not in self.python:
            source = (self.root / path).resolve()
            if not source.is_relative_to(self.root):
                raise OSError('test reference escapes repository')
            tree = ast.parse(source.read_text(encoding='utf-8'))
            functions = {}

            def visit(body, prefix='', test_class=False):
                for node in body:
                    if isinstance(node, ast.ClassDef):
                        is_case = any((isinstance(b, ast.Attribute) and b.attr == 'TestCase')
                                      or (isinstance(b, ast.Name) and b.id == 'TestCase') for b in node.bases)
                        visit(node.body, prefix + node.name + '::', is_case)
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        name = prefix + node.name
                        functions[name] = dict(line=node.lineno, is_test=test_class and node.name.startswith('test'))
            visit(tree.body)
            self.python[path] = functions
        return self.python[path]

    def references(self, evidence):
        found, invalid = [], []
        wire = {PY_ITEM.fullmatch(cite).groups()
                for group in WIRE.findall(evidence) for cite in BACKTICK.findall(group)}
        for cite in BACKTICK.findall(evidence):
            rust = RUST_ITEM.fullmatch(cite)
            python = PY_ITEM.fullmatch(cite)
            if rust:
                path = self.resolve(rust[1])
                if path:
                    found.extend(self.rust_item(path, rust[2]))
            elif python:
                path, item = python.groups()
                try:
                    info = self.python_items(path).get(item)
                except (OSError, SyntaxError, UnicodeError):
                    info = None
                if info and ((path, item) in wire or info['is_test']):
                    found.append(dict(kind='wire-test' if (path, item) in wire else 'python-test',
                                      path=self.resolve_python(path), item=item, line=info['line']))
                elif info is None:
                    invalid.append(dict(cite=cite, status='invalid-test-reference', reason='Python function does not exist'))
            elif cite.endswith('.rs'):
                path = self.resolve(cite)
                tests = self.by_file.get(path, [])
                if path and dedicated_test_file(path) and tests:
                    found.append(dict(kind='rust-test-suite', path=path, test_count=len(tests),
                                      ignored_test_count=sum(t['ignored'] for t in tests)))
            elif cite.endswith('.py'):
                try:
                    tests = [i for i in self.python_items(cite).values() if i['is_test']]
                except (OSError, SyntaxError, UnicodeError):
                    tests = []
                    invalid.append(dict(cite=cite, status='invalid-test-reference', reason='Python source is unavailable or invalid'))
                if tests:
                    found.append(dict(kind='python-test-suite', path=self.resolve_python(cite), test_count=len(tests)))
            elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', cite):
                candidates = self.by_name[cite.split('::')[-1]]
                if len(candidates) == 1 and cite.split('::')[-1] not in self.non_tests:
                    found.extend(candidates)
        unique = {tuple(sorted(reference.items())): reference for reference in found}
        return list(unique.values()), invalid


def inventory(root, paths, resolve, scope, documents):
    index = TestIndex(root, paths, resolve, scope)
    clauses, invalid = [], []
    for document in documents:
        header = None
        for line, text in enumerate(Path(document).read_text(encoding='utf-8').splitlines(), 1):
            _, errors = index.references(text)
            location = dict(md=Path(document).relative_to(root).as_posix(), md_line=line)
            invalid.extend({**location, **error} for error in errors)
            cells = [c.strip() for c in re.split(r'(?<!\\)\|', text)[1:-1]]
            if cells and cells[0] in ('ID', 'Clause') and 'Level' in cells and 'Status' in cells and 'Evidence' in cells:
                header = {value: i for i, value in enumerate(cells)}
                continue
            if not header or len(cells) <= max(header.values()):
                continue
            level, status = cells[header['Level']], cells[header['Status']]
            if not NORMATIVE.search(level) or not re.match(r'^Compliant(?:\s|\(|$)', status):
                continue
            references, _ = index.references(cells[header['Evidence']])
            base = dict(**location, clause=cells[0])
            clauses.append(dict(**base, level=level, role=cells[header['Role']] if 'Role' in header else '',
                                status=status, references=references,
                                finding='test-reference-found' if references else 'missing-test-reference'))
    counts = Counter(c['finding'] for c in clauses)
    return dict(policy='explicit-test-reference-v1', execution_checked=False,
                counts=dict(normative_compliant=len(clauses), with_test_reference=counts['test-reference-found'],
                            missing_test_reference=counts['missing-test-reference']),
                missing=[c for c in clauses if not c['references']], clauses=clauses, invalid_references=invalid)
