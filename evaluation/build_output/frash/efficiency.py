"""FRASH efficiency table"""
from typing import Iterable
from evaluation.build_output._paths import THROUGHPUT, TABLES, generated_by
from evaluation.utils.labels import ALGORITHMS_NS

import pandas as pd

GEN_MAX_DIGITS = 5
DIG_MAX_DIGITS = 2


def _ph(n: int) -> str:
    return r"\phantom{" + "0" * n + "}" if n > 0 else ""

def _fmt_gen(fn_s: int, footnote: str = "") -> str:
    n = int(fn_s)
    if n >= 1000:
        hi, lo = divmod(n, 1000)
        s = f"{hi}{{,}}{lo:03d}"
    else:
        s = str(n)
    pad = GEN_MAX_DIGITS - len(str(n))
    return _ph(pad) + s + footnote

def _fmt_dig(n: int) -> str:
    s = str(n)
    return _ph(DIG_MAX_DIGITS - len(s)) + s

def _fmt_cmp(mpairs: float) -> str:
    return f"{mpairs:.2f}" if mpairs < 1.0 else f"{mpairs:.1f}"


EFFICIENCY_ROWS = [
    (ALGORITHMS_NS.machoke.tex,               "Machoke",           "Machoke",              "Machoke",         "",           False),
    None,
    (ALGORITHMS_NS.fsso.tex,                  "FSS",               "FSS (kappa)",          "FSS (kappa)",     "",           False),
    (ALGORITHMS_NS.fssm.tex,                  "FSS-M",             "FSS-M (kappa)",        "FSS-M (kappa)",   "",           False),
    (ALGORITHMS_NS.fssmw.tex,                 "FSS-MW",            "FSS-MW (kappa)",       "FSS-MW (kappa)",  "",           False),
    None,
    (ALGORITHMS_NS.ccbhash_u.tex,             "CCBHash",           "CCBHash (sim.)",       "CCBHash (sim.)",  "",           False),
    (ALGORITHMS_NS.ccbhash_w.tex,             "CCBHash",           "CCBHash (weights)",    "CCBHash (sim.)",  "",           False),
    None,
    (r"\texttt{FCatalog} (slow)",  "Catalog1 (slow)",  "Catalog1",             "Catalog1",        "",           False),
    (r"\texttt{FCatalog} (Numba)", "Catalog1 (numba)", "Catalog1",             "Catalog1",        "",           False),
    None,
    (ALGORITHMS_NS.bysig_wc.tex,              "ByteSig",           "ByteSig (with-check)", "ByteSig",         "",           True),
]


DIGEST_BYTE_SIZES = {
    "bytesig":   None, # Variable sizes represented as None
    "catalog1":  64,
    "machoke":   4,
    "fss":       16,
    "ccbhash":   16,
}


def get_size_df(algorithms: Iterable) -> pd.DataFrame:
    size_rows = []
    for index in algorithms:
        norm_key = str(index).lower()
        norm_key = norm_key.split(" ")[0]
        norm_key = norm_key.split("-")[0]
        size_rows.append({
            "algorithm": index,
            "digest_bytes": DIGEST_BYTE_SIZES[norm_key]
        })
    return pd.DataFrame(size_rows).set_index("algorithm")


def build_efficiency_table() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    gen_df  = pd.read_csv(THROUGHPUT / "generation_throughput.csv").set_index("algorithm")
    cmp_df  = pd.read_csv(THROUGHPUT / "comparison_throughput.csv").set_index("algorithm")
    size_df = get_size_df(cmp_df.index)

    def gen(k): return int(round(gen_df.loc[k,  "functions_per_sec"]))  #type: ignore
    def cmp(k): return cmp_df.loc[k,  "pairs_per_sec"] / 1e6            #type: ignore
    def dig(k): return int(size_df.loc[k, "digest_bytes"])              #type: ignore

    lines = []
    for row in EFFICIENCY_ROWS:
        if row is None:
            lines.append(r"\cmidrule(r){1-1}\cmidrule(l){2-4}")
            continue
        disp, gk, ck, sk, fn_note, var_dig = row
        dig_s = r"var." if var_dig else _fmt_dig(dig(sk))
        lines.append(
            f"    {disp:<30} & {dig_s:<22}"
            f" & {_fmt_gen(gen(gk), fn_note):<22} & {_fmt_cmp(cmp(ck))} \\\\"  #type: ignore
        )

    body = "\n".join(lines)
    tex = generated_by(__file__) + (
        r"\resizebox{\linewidth}{!}{%" "\n"
        r"\begin{tabular}{lrrr}" "\n"
        r"\toprule" "\n"
        r"\textbf{Algorithm}" "\n"
        r"  & \multicolumn{1}{c}{\textbf{Size}}" "\n"
        r"  & \multicolumn{1}{c}{\textbf{Generation}}" "\n"
        r"  & \multicolumn{1}{c}{\textbf{Comparison}} \\" "\n"
        
        r"  & \multicolumn{1}{c}{\footnotesize{(bytes)}}" "\n"
        r"  & \multicolumn{1}{c}{\footnotesize{(digests/s)}}" "\n"
        r"  & \multicolumn{1}{c}{\footnotesize{(M.pairs/s)}} \\" "\n"
        
        r"\midrule" "\n"
        f"{body}\n"
        
        r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"}%"
    )
    out = TABLES / "tab_efficiency.tex"
    out.write_text(tex)
    print(f"  Saved -> {out}")


if __name__ == "__main__":
    build_efficiency_table()
