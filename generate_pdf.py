import markdown
from weasyprint import HTML, CSS
import os

input_file = '/Users/ayangain/.gemini/antigravity-ide/brain/d2d2fde4-787e-4784-a709-66d623e97758/comprehensive_project_report.md'
output_file = '/Users/ayangain/Desktop/F_TAG_Comprehensive_Report.pdf'

with open(input_file, 'r', encoding='utf-8') as f:
    text = f.read()

# Render Markdown to HTML
html_content = markdown.markdown(text, extensions=['tables', 'fenced_code'])

# Wrap in a basic HTML template for better styling
full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Helvetica', 'Arial', sans-serif; line-height: 1.6; margin: 40px; color: #333; }}
        h1, h2, h3 {{ color: #111; }}
        h1 {{ border-bottom: 2px solid #eaeaea; padding-bottom: 10px; }}
        h2 {{ border-bottom: 1px solid #eaeaea; padding-bottom: 5px; margin-top: 30px; }}
        code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 8px; overflow-x: auto; }}
        pre code {{ background-color: transparent; padding: 0; }}
        ul, ol {{ margin-bottom: 20px; }}
        li {{ margin-bottom: 5px; }}
    </style>
</head>
<body>
    {html_content}
</body>
</html>
"""

# Generate PDF
HTML(string=full_html).write_pdf(output_file)
print(f"Successfully generated {output_file}")
