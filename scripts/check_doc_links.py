#!/usr/bin/env python3
"""Check repository Markdown links offline; HTTP/release URLs are external.

Checks inline/reference links, images, HTML href/src, and Markdown heading/HTML
anchors. Ignores code and comments. It does not certify external availability or
non-Markdown fragments. Missing generated artifacts are not silently exempted:
link to their release URL or describe the generated path as code instead.
"""
import argparse
from collections import Counter
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def visible(text, inline=True):
    """Preserve offsets/newlines while masking non-rendered Markdown regions."""
    def blank(match):
        return re.sub(r'[^\n]', ' ', match.group())

    text = re.sub(r'<!--[\s\S]*?(?:-->|\Z)', blank, text)
    tags = 'pre|code' if inline else 'pre'
    text = re.sub(r'<(' + tags + r')\b[^>]*>[\s\S]*?</\1\s*>', blank, text, flags=re.I)
    lines, fence = [], None
    for line in text.splitlines(keepends=True):
        marker = re.match(r' {0,3}(`{3,}|~{3,})(.*)', line)
        masked = fence is not None
        if marker:
            run, rest = marker.groups()
            if fence is None:
                fence = run
                masked = True
            elif run[0] == fence[0] and len(run) >= len(fence) and not rest.strip():
                fence = None
        if masked or line.startswith(('    ', '\t')):
            line = re.sub(r'[^\n]', ' ', line)
        lines.append(line)
    text = ''.join(lines)
    if inline:
        text = re.sub(r'(`+)(?!`)([\s\S]*?)(?<!`)\1(?!`)', blank, text)
    return text


def closing(text, start, left='[', right=']'):
    depth = 0
    for index in range(start, len(text)):
        if index and text[index - 1] == '\\':
            continue
        if text[index] == left:
            depth += 1
        elif text[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def destination(text, start):
    start += len(text[start:]) - len(text[start:].lstrip())
    if start == len(text):
        return None
    if text[start] == '<':
        end = text.find('>', start + 1)
        return text[start + 1:end] if end >= 0 else None
    depth, end = 0, start
    while end < len(text):
        char = text[end]
        if end and text[end - 1] == '\\':
            end += 1
            continue
        if char == '(':
            depth += 1
        elif char == ')':
            if depth == 0:
                break
            depth -= 1
        elif char.isspace() and depth == 0:
            break
        end += 1
    return text[start:end] if depth == 0 else None


class HtmlLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for attr in ('href', 'src'):
            if attrs.get(attr) is not None:
                self.links.append((self.getpos()[0], attrs[attr]))
        for attr in ('id', 'name') if tag == 'a' else ('id',):
            if attrs.get(attr):
                self.ids.add(attrs[attr])


def anchors(text):
    text = visible(text, inline=False)
    parser = HtmlLinks()
    parser.feed(text)
    result, headings = set(parser.ids), set()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r' {0,3}#{1,6}\s+(.+?)\s*#*\s*$', line)
        title = match[1] if match else None
        if (title is None and index + 1 < len(lines) and line.strip()
                and re.fullmatch(r' {0,3}(?:=+|-+)\s*', lines[index + 1])):
            title = line.strip()
        if title is None:
            continue
        title = re.sub(r'!?\[([^\]]*)\]\([^)]*\)', r'\1', title)
        title = html.unescape(re.sub(r'<[^>]*>', '', title)).replace('`', '').replace('*', '')
        title = re.sub(r'(?<!\w)(_+)(.+?)\1(?!\w)', r'\2', title)
        slug = re.sub(r'[^\w\- ]', '', title.lower()).replace(' ', '-')
        candidate, suffix = slug, 0
        while candidate in headings:
            suffix += 1
            candidate = f'{slug}-{suffix}'
        headings.add(candidate)
        result.add(candidate)
    return result


def links(text):
    text = visible(text)
    definitions, records = {}, []
    definition_pattern = r'(?m)^ {0,3}\[([^\]\n]+)\]:[ \t]*(.*)$'
    normalize = lambda value: ' '.join(value.split()).casefold()
    for match in re.finditer(definition_pattern, text):
        target = destination(match[2], 0)
        if target is not None:
            definitions.setdefault(normalize(match[1]), target)
            records.append((text.count('\n', 0, match.start()) + 1, target))
    text = re.sub(definition_pattern, lambda m: ' ' * len(m.group()), text)
    reference_tails = set()
    for match in re.finditer(r'(?<!\\)\[', text):
        if match.start() in reference_tails:
            continue
        end = closing(text, match.start())
        if end is None:
            continue
        label = text[match.start() + 1:end]
        following = text[end + 1:]
        target = None
        if following.startswith('(') and closing(text, end + 1, '(', ')') is not None:
            target = destination(text, end + 2)
        elif following.startswith('['):
            ref_end = closing(text, end + 1)
            if ref_end is not None:
                reference_tails.add(end + 1)
                key = text[end + 2:ref_end] or label
                target = definitions.get(normalize(key))
        elif normalize(label) in definitions:
            target = definitions[normalize(label)]
        if target is not None:
            records.append((text.count('\n', 0, match.start()) + 1, target))
    parser = HtmlLinks()
    parser.feed(text)
    return records + parser.links


def check(root, documents):
    root = Path(root).resolve()
    counts, problems, cache = Counter(), [], {}
    for document in sorted(set(Path(p) for p in documents)):
        name = document.as_posix()
        try:
            if document.is_absolute() or not (root / document).resolve().is_relative_to(root):
                raise ValueError('document must be inside the repository')
            contents = (root / document).read_text(encoding='utf-8')
        except (OSError, UnicodeError, ValueError) as error:
            problems.append(dict(document=name, line=0, target='', reason=f'cannot read document: {error}'))
            continue
        counts['documents'] += 1
        for line, raw in links(contents):
            counts['links'] += 1
            target = html.unescape(re.sub(r'\\([\\`*{}\[\]()#+.!_<>-])', r'\1', raw))
            reason = None
            try:
                url = urlsplit(target)
                if url.scheme in ('http', 'https') and not url.netloc:
                    raise ValueError('HTTP URL has no host')
                if url.scheme in ('http', 'https', 'mailto', 'tel', 'data') or (not url.scheme and url.netloc):
                    counts['external'] += 1
                    continue
                if url.scheme:
                    reason = 'unsupported URL scheme'
                else:
                    path = unquote(url.path)
                    if path:
                        parent = root if path.startswith('/') else (root / document).parent
                        resolved = (parent / path.lstrip('/')).resolve()
                    else:
                        resolved = (root / document).resolve()
                    if not resolved.is_relative_to(root):
                        reason = 'target escapes repository'
                    elif not resolved.exists():
                        reason = 'missing local target'
                    elif url.fragment:
                        if resolved.is_dir():
                            resolved = resolved / 'README.md'
                        if resolved.suffix.lower() == '.md' and resolved.is_file():
                            if resolved not in cache:
                                cache[resolved] = anchors(resolved.read_text(encoding='utf-8'))
                            if unquote(url.fragment) not in cache[resolved]:
                                reason = 'missing Markdown anchor'
                        else:
                            counts['unverified_fragments'] += 1
            except (OSError, UnicodeError, ValueError) as error:
                reason = f'invalid target: {error}'
            if reason:
                problems.append(dict(document=name, line=line, target=raw, reason=reason))
            else:
                counts['local'] += 1
    return dict(counts=dict(counts), problems=problems)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('documents', nargs='*', help='repository-relative Markdown paths; default: Git-visible Markdown')
    args = parser.parse_args()
    try:
        documents = args.documents or subprocess.check_output(
            ['git', '-C', str(args.root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', '*.md'],
            text=True).split('\0')
        documents = [name for name in documents if name]
        if not documents:
            raise ValueError('no Markdown documents found')
        result = check(args.root, documents)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        result = dict(counts={}, problems=[dict(document='', line=0, target='', reason=str(error))])
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('Documentation links:', result['counts'])
        for problem in result['problems']:
            print(f"{problem['document']}:{problem['line']}: {problem['reason']}: {problem['target']}")
    return int(bool(result['problems']))


if __name__ == '__main__':
    sys.exit(main())
