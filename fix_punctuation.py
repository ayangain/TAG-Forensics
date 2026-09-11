import re

with open("author.tex", "r") as f:
    text = f.read()

# Replace semicolons not preceded by \ (ignoring \;)
# We'll use a regex that looks for ; not preceded by \
text = re.sub(r'(?<!\\);', ',', text)

# Replace --- with ,
text = re.sub(r'\s*---\s*', ', ', text)

# Replace -- with " to " for ranges if between digits or brackets, otherwise replace with ,
text = re.sub(r'([0-9\}])--([0-9W])', r'\1 to \2', text)
text = re.sub(r'\s*--\s*', ', ', text)

with open("author.tex", "w") as f:
    f.write(text)
print("Replacements done.")
