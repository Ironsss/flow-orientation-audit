"""Build the arXiv package from manuscript_submission/ (single source of truth).

Run from anywhere:  python manuscript_submission/make_arxiv.py
Output: manuscript_submission/arxiv/{main.pdf, arxiv_submission.zip}
With --neutral: manuscript_submission/preprint/{main.pdf, supplementary.pdf}, no venue name in the
footer (for preprint servers other than arXiv).

arXiv ships elsarticle, so the sources are used as-is except for the journal banner
(the manuscript was drafted for JISA, which is on hold).
The supplementary material goes in as an ancillary file (anc/), not in the paper.
Needs: pdflatex + bibtex (MiKTeX/TeX Live). arXiv wants main.bbl, not the .bib.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

S = pathlib.Path(__file__).parent
NEUTRAL = "--neutral" in sys.argv
A = S / ("preprint" if NEUTRAL else "arxiv")
FIGS = ("fig_orientation.pdf", "fig_unsw_ecdf.pdf")
VENUE = "" if NEUTRAL else "arXiv"
# elsarticle can print "Preprint submitted to <journal>" on page 1; neutral mode drops that footer.
NOFOOT = (r"\makeatletter\def\ps@pprintTitle{\let\@oddhead\@empty\let\@evenhead\@empty"
          r"\def\@oddfoot{\centerline{\thepage}}\let\@evenfoot\@oddfoot}\makeatother" + "\n")

A.mkdir(exist_ok=True)
(A / "figures").mkdir(exist_ok=True)


def stamp(s):
    s, k = re.subn(r"\\journal\{[^}]*\}", lambda m: "\\journal{" + VENUE + "}", s)
    assert k == 1, "expected exactly one \\journal{...}"
    return s.replace("\\begin{document}", NOFOOT + "\\begin{document}", 1) if NEUTRAL else s


for name in ("main.tex", "supplementary.tex"):
    (A / name).write_text(stamp((S / name).read_text(encoding="utf-8")), encoding="utf-8")
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
if NEUTRAL:
    print("OK", A / "main.pdf", A / "supplementary.pdf")
    sys.exit(0)

with zipfile.ZipFile(A / "arxiv_submission.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for f in ("main.tex", "main.bbl", *(f"figures/{x}" for x in FIGS)):
        z.write(A / f, f)
    z.write(A / "supplementary.pdf", "anc/supplementary.pdf")
print("OK", A / "arxiv_submission.zip")
