# BinRankBench

**BinRankBench** is an open-source framework for evaluating cross-platform
binary function similarity using fuzzy hashing algorithms.

## Original publication

BinRankBench contains the code to reproduce the results published in our
Computers & Security paper:

> Bucci, Valerio, Oluwafemi Olukoya, and Jesús Martínez del Rincón.
> *"Bridging the compilation gap: A taxonomy and evaluation of fuzzy hashes
> for Binary Function Similarity Analysis."*
> Computers & Security (2026): 105077.

The paper can be accessed at this link:
<https://doi.org/10.1016/j.cose.2026.105077>.

Our [dataset on Zenodo](https://doi.org/10.5281/zenodo.20439492) allows to
reproduce all the paper results without re-running the binary analysis phase.

It comes with the radare2 artefacts extracted from Cisco-Talos Dataset-1 and
a PostgreSQL dump with the generated fuzzy hashes for 4,278,822 functions.

## Algorithms

- **CCBHash:** Concatenates 13 weighted sub-hashes.
- **FSS (Original):** Unweighted SimHash over mnemonics, immediate values, and
                  CFG graphlets (by Thomas Dullien).
- **FSS (Marcelli):** Unweighted SimHash over mnemonics and CFG graphlets
                  (by Marcelli et al.).
- **FSS (Marcelli-Weighted):** SimHash with feature-type weights
                           (mnemonics 0.05; graphlets 1.00).
- **FCatalog:** MinHash approach on 4-byte shingles, applying Catalog1 at the
            function level.
- **Machoke:** MurmurHashv3 on CFG string representation.
- **Position Independent Code:** Function bytes with nibble-level masking from
                             radare2 Zignatures.

## Documentation

- [Installation](docs/installation.md):
  requirements (Python, Docker, radare2, bin2ml)
- [Quickstart](docs/quickstart.md):
  reproduce paper results from the Zenodo dump
- [Pipeline](docs/pipeline.md):
  full pipeline reference (extract, ingest, evaluate)
- [Extending](docs/extending.md):
  add a new similarity strategy

## How to cite our work

Please use the following BibTeX:

```plaintext
@article{bucciBridgingCompilationGap2026,
  title = {Bridging the Compilation Gap: A Taxonomy and Evaluation of Fuzzy Hashes for Binary Function Similarity Analysis},
  shorttitle = {Bridging the Compilation Gap},
  author = {Bucci, Valerio and Olukoya, Oluwafemi and {Mart{\'i}nez del Rinc{\'o}n}, Jes{\'u}s},
  year = 2026,
  month = dec,
  journal = {Computers \& Security},
  volume = {171},
  pages = {105077},
  issn = {0167-4048},
  doi = {10.1016/j.cose.2026.105077},
  url = {https://www.sciencedirect.com/science/article/pii/S0167404826002531},
}
```

## Licence

BinRankBench is released under the
**GNU General Public License v3.0** or any later version.

See [`LICENCE`](./LICENCE) for the full text.

This framework reimplements algorithms from several open-source projects with
their own licences (Apache 2.0, MIT, GPL v3, LGPL v3).
See [`LICENCES/THIRD-PARTY.md`](./LICENCES/THIRD-PARTY.md) for attributions.
