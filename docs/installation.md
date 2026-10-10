# Installation

## Python

Clone the repository and install dependencies:

```bash
# Clone the repo
git clone https://github.com/valbucci/binrankbench
cd binrankbench

# Recommended: setup a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: install FunctionSimSearch
pip install third-party/functionsimsearch-*.whl
pip install third-party/marcellisimsearch-*.whl
```

All commands run as `python -m binrankbench <command>` from the repo root.

## Docker (optional)

Only needed to run BinRankBench in a container or to avoid installing Python
dependencies locally. Install [Docker](https://docs.docker.com/get-docker/) and
[Docker Compose](https://docs.docker.com/compose/install/).

The `app` service in `docker-compose.yml` provides the Python environment.
The `db` service provides the database (PostgreSQL).

## PostgreSQL

Required for the ingestion and evaluation stages. The simplest setup:

```bash
cp .env.example .env    # review credentials; defaults work out of the box
docker compose up -d db
```

For a local PostgreSQL installation, set `DB_URL` in `.env` accordingly.

## radare2 (optional)

Only needed to re-extract features from raw binaries instead of using the
[dataset on Zenodo](https://doi.org/10.5281/zenodo.20439492).

This version of BinRankBench was developed and tested against **radare2 6.0.4**.
Other versions may produce different results.

Build from source:

```bash
git clone https://github.com/radareorg/radare2
cd radare2 && git checkout 6.0.4
sys/install.sh
```

Verify the installed version:

```bash
r2 -v
```

## bin2ml (optional)

[bin2ml](https://github.com/valbucci/bin2ml) wraps radare2 and produces the
JSON/binary files that BinRankBench ingests. Only needed for re-extraction from
raw binaries.

This publication was tested against commit `0bc7159`.
Build from that exact revision:

```bash
git clone https://github.com/valbucci/bin2ml.git
cd bin2ml
git checkout 0bc7159
cargo build --release
cp target/release/bin2ml /usr/local/bin/
```

Verify:

```bash
bin2ml --version
```

The `ingestion` Docker service (`docker-compose.yml`) builds this pinned commit
from source automatically.
