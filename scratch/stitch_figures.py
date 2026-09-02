"""Stitch fig_fwoc.png (panel a) and afconf_roc.png (panel b) into fig_fwoc_afconf.png."""
from PIL import Image

fwoc = Image.open("Figures/fig_fwoc.png")
roc = Image.open("experiment/results/afconf_roc.png")

# Match heights
target_height = max(fwoc.height, roc.height)

def resize_to_height(img, h):
    scale = h / img.height
    return img.resize((int(img.width * scale), h), Image.Resampling.LANCZOS)

fwoc_r = resize_to_height(fwoc, target_height)
roc_r = resize_to_height(roc, target_height)

gap = 30
combined = Image.new('RGB',
                     (fwoc_r.width + gap + roc_r.width, target_height),
                     (255, 255, 255))
combined.paste(fwoc_r, (0, 0))
combined.paste(roc_r, (fwoc_r.width + gap, 0))
combined.save("Figures/fig_fwoc_afconf.png", quality=95)
print(f"[OK] fig_fwoc_afconf.png ({combined.width}x{combined.height})")
