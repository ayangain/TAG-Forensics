import re

with open('author.tex') as f:
    text = f.read()

# Let's inspect the aux file or find how each \ref resolves!
with open('author.aux') as f:
    aux = f.read()

aux_labels = {}
for line in aux.split('\n'):
    m = re.match(r'\\newlabel\{([^}]+)\}\{\{([^}]+)\}\{([^}]+)\}', line)
    if m:
        label, num, page = m.group(1), m.group(2), m.group(3)
        aux_labels[label] = (num, page)

lines = text.split('\n')
for line_no, line in enumerate(lines, 1):
    for m in re.finditer(r'([A-Za-z~\\ ]*)\\ref\{([^}]+)\}', line):
        prefix = m.group(1).strip()
        label = m.group(2)
        resolved = aux_labels.get(label, ('??', '??'))
        print(f"L{line_no:3d}: context='{prefix}\\ref{{{label}}}' -> resolves to '{resolved[0]}' (p.{resolved[1]})")
