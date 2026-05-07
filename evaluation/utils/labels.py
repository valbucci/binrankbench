"""Algorithm display name registry.

Edit this file to update any algorithm label across all figures and tables.

``A.<key>`` provides:

- ``.base``   -- short figure label for recall-curve figures (one line per algorithm)
- ``.score``  -- figure label for scoring-method figures (robustness, XO kappa variant)
- ``.hsim``   -- XO figure label for the h-sim variant; ``None`` if not shown separately
- ``.tex``    -- LaTeX ``\\texttt{}`` cell for table columns
- ``.colour`` -- colour family key for XO sensitivity figure grouping
"""
from types import SimpleNamespace as _NS


def _alg(base: str, tex: str, colour: str,
         score: str | None = None, hsim: str | None = None) -> _NS:
    return _NS(base=base, tex=tex, colour=colour,
               score=score if score is not None else base, hsim=hsim)


ALGORITHMS_NS = _NS(
    machoke   = _alg("Machoke",   r"\texttt{Machoke}",              "Machoke"),
    ccbhash_w = _alg("CCBHash-W", r"\texttt{CCBHash-W}",            "CCBHash"),
    ccbhash_u = _alg("CCBHash-U", r"\texttt{CCBHash-U}",            "CCBHash"),
    fsso      = _alg("FSS",       r"\texttt{FSS}",                  "FSS",
                     score="FSS-kappa",    hsim="FSS-h-sim"),
    fssm      = _alg("FSSM",      r"\texttt{FSSM}",                 "FSS-M",
                     score="FSS-M-kappa",  hsim="FSS-M-h-sim"),
    fssmw     = _alg("FSSM-W",    r"\texttt{FSSM-W}",               "FSS-MW",
                     score="FSS-MW-kappa", hsim="FSS-MW-h-sim"),
    cat1      = _alg("FCatalog",  r"\texttt{FCatalog}",             "Catalog1"),
    bysig_wc  = _alg("PIC Sig.",  r"\texttt{PIC Sig.}",             "ByteSig"),
)
