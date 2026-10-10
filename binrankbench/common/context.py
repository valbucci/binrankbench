"""Package-level path constants for BinRankBench resources and data directories."""

from pathlib import Path

PKG_DIR = Path(__file__).parent.parent.resolve()
ROOT_DIR = PKG_DIR.parent.resolve()
DATA_DIR = ROOT_DIR / "data"
THIRD_PARTY_DIR = ROOT_DIR / "third-party"


def _find_bin2ml() -> Path:
    import shutil

    on_path = shutil.which("bin2ml")
    if on_path:
        return Path(on_path)
    return THIRD_PARTY_DIR / "bin2ml"


BIN2ML_PATH = _find_bin2ml()
