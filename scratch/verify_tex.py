import re

with open("author.tex", "r") as f:
    text = f.read()
    
if "0.90 $\\pm$ 0.08" in text:
    print("Found 0.90 in author.tex")
else:
    print("Did NOT find 0.90 in author.tex")
    
if "1.00*" in text:
    print("Found 1.00* in author.tex")
