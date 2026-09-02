from PIL import Image

# The original stitched image is (3610, 1029).
# The new ROC curve is (1409, 1176). The scaled width is ~1232.
# 3610 - 1232 = 2378.
img = Image.open("Figures/fig_fwoc_afconf.png")
left_half = img.crop((0, 0, 2378, 1029))
left_half.save("Figures/fig_fwoc.png")
print("Extracted fig_fwoc.png")
