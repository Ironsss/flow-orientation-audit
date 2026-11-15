"""Build the arXiv package from manuscript_submission/ (single source of truth).

Run from anywhere:  python manuscript_submission/make_arxiv.py
Output: manuscript_submission/arxiv/{main.pdf, arxiv_submission.zip}

arXiv ships elsarticle, so the sources are used as-is except for the journal banner
(the manuscript was drafted for JISA, which is on hold).
The supplementary material goes in as an ancillary file (anc/), not in the paper.
Needs: pdflatex + bibtex (MiKTeX/TeX Live). arXiv wants main.bbl, not the .bib.
"""
import pathlib
import re
import shutil
import subprocess
import zipfile

S = pathlib.Path(__file__).parent
A = S / "arxiv"
FIGS = ("fig_orientation.pdf", "fig_unsw_ecdf.pdf")

A.mkdir(exist_ok=True)
(A / "figures").mkdir(exist_ok=True)

src = (S / "main.tex").read_text(encoding="utf-8")
# The preprint must not claim a journal; elsarticle prints "Preprint submitted to <journal>".
src, n = re.subn(r"\\journal\{[^}]*\}", r"\\journal{arXiv}", src)
assert n == 1, "expected exactly one \\journal{...}"
(A / "main.tex").write_text(src, encoding="utf-8")
sm = (S / "supplementary.tex").read_text(encoding="utf-8")
sm = re.sub(r"\\journal\{[^}]*\}", r"\\journal{arXiv}", sm)
(A / "supplementary.tex").write_text(sm, encoding="utf-8")
shutil.copy(S / "references.bib", A)
for f in FIGS:
    shutil.copy(S / "figures" / f, A / "figures" / f)


def build(d, name):
    stem = name.removesuffix(".tex")
    tex = ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", name]
    # not latexmk: it needs Perl, absent on some Windows setups
    for cmd in (tex, ["bibtex", stem], tex, tex):
        subprocess.run(cmd, cwd=d, check=True, stdout=subprocess.DEVNULL)


build(A, "main.tex")
build(A, "supplementary.tex")  # ancillary file

with zipfile.ZipFile(A / "arxiv_submission.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for f in ("main.tex", "main.bbl", *(f"figures/{x}" for x in FIGS)):
        z.write(A / f, f)
    z.write(A / "supplementary.pdf", "anc/supplementary.pdf")
print("OK", A / "arxiv_submission.zip")
