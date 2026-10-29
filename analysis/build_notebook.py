#!/usr/bin/env python3
"""Convert threat_report.py (percent format) into threat_report.ipynb.

Dependency-free (stdlib only): `# %%` starts a code cell, `# %% [markdown]`
starts a markdown cell whose lines are commented with `# `.
"""
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "threat_report.py").read_text(encoding="utf-8")
dst = Path(sys.argv[2] if len(sys.argv) > 2 else "threat_report.ipynb")

cells = []
for chunk in re.split(r"(?m)^# %%", src):
    if not chunk.strip():
        continue
    header, _, body = chunk.partition("\n")
    lines = body.rstrip("\n").split("\n")
    if "[markdown]" in header:
        text = [re.sub(r"^# ?", "", ln) for ln in lines]
        cells.append({"cell_type": "markdown", "metadata": {},
                      "source": [ln + "\n" for ln in text[:-1]] + [text[-1]]})
    else:
        cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
                      "source": [ln + "\n" for ln in lines[:-1]] + [lines[-1]]})

nb = {"cells": cells, "nbformat": 4, "nbformat_minor": 5,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python"}}}
dst.write_text(json.dumps(nb, indent=1), encoding="utf-8")
print(f"wrote {dst} ({len(cells)} cells)")
