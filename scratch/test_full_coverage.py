from typing import Tuple

def check_cov(fwoc: Tuple[int, int], tc: Tuple[int, int]):
    fwoc_start, fwoc_end = fwoc
    tc_start, tc_end = tc
    full_coverage = (fwoc_start <= tc_start and fwoc_end >= tc_end)
    return full_coverage

print(check_cov((0, 4), (2, 4)))
