import sys
import os
import re
import markdown
import weasyprint

def md_to_html(md_text, title="Document"):
    # Convert math delimiters for clean HTML rendering
    # Double dollar $$...$$ to div block
    def replace_block_math(match):
        expr = match.group(1).strip()
        return f'<div class="math-block">\\[ {expr} \\]</div>'
    
    # Inline math $...$
    def replace_inline_math(match):
        expr = match.group(1).strip()
        return f'<span class="math-inline">\\( {expr} \\)</span>'

    # Process math blocks
    html_md = re.sub(r'\$\$(.*?)\$\$', replace_block_math, md_text, flags=re.DOTALL)
    html_md = re.sub(r'\$(.*?)\$', replace_inline_math, html_md)

    # Convert markdown to HTML with standard extensions
    extensions = ['tables', 'fenced_code', 'toc', 'nl2br', 'sane_lists']
    html_content = markdown.markdown(html_md, extensions=extensions)

    # Custom styling for academic publication quality
    css_style = """
    @page {
        size: A4;
        margin: 20mm 18mm 20mm 18mm;
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            font-size: 9pt;
            color: #666;
        }
        @bottom-left {
            content: "TAG-Forensics Research";
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            font-size: 9pt;
            color: #666;
        }
    }

    body {
        font-family: 'Georgia', 'Times New Roman', serif;
        font-size: 10.5pt;
        line-height: 1.6;
        color: #1a1a1a;
    }

    h1, h2, h3, h4, h5, h6 {
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        color: #0f2942;
        font-weight: 700;
        margin-top: 1.4em;
        margin-bottom: 0.5em;
        page-break-after: avoid;
    }

    h1 {
        font-size: 20pt;
        border-bottom: 2px solid #0f2942;
        padding-bottom: 6px;
        margin-top: 0;
    }

    h2 {
        font-size: 14pt;
        border-bottom: 1px solid #d0d7de;
        padding-bottom: 4px;
    }

    h3 {
        font-size: 12pt;
    }

    p {
        margin-top: 0;
        margin-bottom: 1em;
        text-align: justify;
    }

    a {
        color: #0969da;
        text-decoration: none;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 1.2em 0;
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        font-size: 9pt;
        page-break-inside: avoid;
    }

    th, td {
        border: 1px solid #d0d7de;
        padding: 6px 10px;
        text-align: left;
    }

    th {
        background-color: #f6f8fa;
        color: #0f2942;
        font-weight: bold;
    }

    tr:nth-child(even) {
        background-color: #fcfcfc;
    }

    code {
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 9.5pt;
        background-color: #f6f8fa;
        padding: 2px 4px;
        border-radius: 3px;
    }

    pre {
        background-color: #f6f8fa;
        border: 1px solid #e1e4e8;
        padding: 10px;
        border-radius: 4px;
        overflow-x: auto;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 8.5pt;
        line-height: 1.45;
        page-break-inside: avoid;
    }

    blockquote {
        margin: 1em 0;
        padding: 8px 16px;
        color: #24292e;
        background-color: #f0f7ff;
        border-left: 4px solid #0969da;
        page-break-inside: avoid;
    }

    ul, ol {
        margin-top: 0;
        margin-bottom: 1em;
        padding-left: 1.5em;
    }

    li {
        margin-bottom: 0.3em;
    }

    .math-block {
        text-align: center;
        margin: 1em 0;
        font-family: 'Times New Roman', serif;
        font-style: italic;
        font-size: 11pt;
    }

    .math-inline {
        font-family: 'Times New Roman', serif;
        font-style: italic;
    }

    hr {
        border: none;
        border-top: 1px solid #d0d7de;
        margin: 1.5em 0;
    }
    """

    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>{css_style}</style>
</head>
<body>
    {html_content}
</body>
</html>
"""
    return full_html

def convert_file(input_md_path, output_pdf_path):
    print(f"Reading {input_md_path}...")
    with open(input_md_path, 'r', encoding='utf-8') as f:
        md_text = f.read()
    
    title = os.path.basename(input_md_path).replace('.md', '').replace('_', ' ').title()
    html_text = md_to_html(md_text, title=title)
    
    print(f"Generating PDF: {output_pdf_path}...")
    weasyprint.HTML(string=html_text).write_pdf(output_pdf_path)
    print(f"Successfully generated {output_pdf_path} ({os.path.getsize(output_pdf_path)} bytes)")

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Files to convert
    files = [
        ('research_gaps_and_approaches.md', 'research_gaps_and_approaches.pdf'),
        ('draft_sections_3_5.md', 'draft_sections_3_5.pdf')
    ]
    
    for md_file, pdf_file in files:
        md_path = os.path.join(base_dir, md_file)
        pdf_path = os.path.join(base_dir, pdf_file)
        if os.path.exists(md_path):
            convert_file(md_path, pdf_path)
        else:
            print(f"File not found: {md_path}")
