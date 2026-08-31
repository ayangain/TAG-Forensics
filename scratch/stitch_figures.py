from PIL import Image

fwoc = Image.open("Figures/fig_fwoc.png")
roc = Image.open("experiment/results/afconf_roc.png")

target_height = fwoc.height
scale = target_height / roc.height
new_width = int(roc.width * scale)
roc_resized = roc.resize((new_width, target_height), Image.Resampling.LANCZOS)

combined = Image.new('RGB', (fwoc.width + roc_resized.width, target_height))
combined.paste(fwoc, (0, 0))
combined.paste(roc_resized, (fwoc.width, 0))
combined.save("Figures/fig_fwoc_afconf.png")
