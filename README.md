# BinRankBench

**BinRankBench** is an open-source framework for evaluating cross-platform
binary function similarity using fuzzy hashing algorithms.
It accompanies the paper:

> *SoK: The Semantic Gap in Fuzzy Hashing — A Taxonomy and Evaluation of
> Cross-Platform Binary Function Similarity Analysis at Scale*
> Valerio Bucci, Oluwafemi Olukoya, Jesús Martínez del Rincón
> Queen's University Belfast

A **pre-loaded PostgreSQL database dump** with fuzzy hashes for 4,278,822
functions from Cisco-Talos Dataset-1 is available on Zenodo, so reviewers can
reproduce all paper results without re-running the binary analysis phase.

## Algorithms

| Strategy | Description |
|---|---|
| **CCBHash** | Composite hash over 13 weighted semantic and structural features |
| **FSS (Original)** | SimHash over mnemonics, immediate values, and CFG graphlets (Dullien/Google Project Zero) |
| **FSS (Marcelli)** | FSS over mnemonics and CFG graphlets only; immediate values are absent because Marcelli et al.'s fix targets Capstone's `#0x…` format and has no effect under radare2 |
| **FSS (Marcelli-Weighted)** | FSS (Marcelli) with per-feature-type weights: mnemonics 0.05, graphlets 1.00, immediates 4.00; the immediate weight has no effect since no immediates are extracted |
| **Catalog1** | MinHash-based approach faithful to the FCatalog implementation |
| **Machoke** | Graph-feature hash based on the Machoke descriptor |
| **Byte Signatures** | Radare2-style bit-masked byte-level signatures |

## Documentation

- [docs/installation.md](docs/installation.md) — requirements (Python, Docker, radare2, bin2ml)
- [docs/quickstart.md](docs/quickstart.md) — reproduce paper results from the Zenodo dump
- [docs/pipeline.md](docs/pipeline.md) — full pipeline reference (extract, ingest, evaluate)
- [docs/extending.md](docs/extending.md) — add a new similarity strategy

## Regression Tests

```bash
pytest -m regression          # run regression tests only
pytest -m "not regression"    # skip regression tests
```

## License

BinRankBench is released under the **GNU General Public License v3.0**.
See [`LICENSE`](LICENSE) for the full text.

This framework reimplements algorithms from several open-source projects with
their own licenses (Apache 2.0, MIT, GPL v3, LGPL v3).
See [`LICENSES/THIRD-PARTY.md`](LICENSES/THIRD-PARTY.md) for attributions.
