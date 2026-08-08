#!/usr/bin/env python3
"""Extract release notes from CHANGELOG.rst for a given tag."""
import os
import re

tag = os.environ['TAG']
repo = os.environ['REPO']

with open('CHANGELOG.rst') as f:
    text = f.read()

# A version heading is "vX.Y.Z YYYY/MM/DD" on its own line.
heading = r'^v[\d.]+ [\d/]+$'

# Find all version headings
versions = re.findall(heading, text, re.MULTILINE)


def is_rst_underline(line):
    """RST heading underline: one of ~=-^ repeated 3+ times."""
    return len(line) >= 3 and line[0] in '~=-^' and len(set(line)) == 1


# Find current version's section
escaped = re.escape(tag)
# Negative lookahead so "v1.0.1" does not match a "v1.0.1.dev0" heading.
pattern = r'^' + escaped + r'(?![\d.])' + r'.*?(?=' + heading + r'|\Z)'
m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
if m:
    notes = m.group(0).strip()
    # Drop the RST-style heading line and its underline.
    # e.g. "v5.3.2 2026/07/24\n~~~~~~~~~~~~~~~~~~~" -> remove both.
    lines = notes.splitlines()
    if len(lines) >= 2 and is_rst_underline(lines[1]):
        notes = '\n'.join(lines[2:]).strip()
else:
    notes = ''

# Find previous version in the same major.minor series for changelog link
prefix = tag.rsplit('.', 1)[0]
prev = ''
found = False
for v in versions:
    if v == tag:
        found = True
        continue
    if found and v.startswith(prefix):
        prev = v
        break
if prev:
    notes += '\n\n**Full Changelog**: https://github.com/' + repo + '/compare/' + prev + '...' + tag

with open('release_notes.md', 'w') as f:
    f.write(notes + '\n')
