import pytest
import subprocess
import re
from pathlib import Path

from binrankbench.common.bin2ml import Bin2MLError, BinaryDataTracker
from binrankbench.common.context import BIN2ML_PATH


@pytest.fixture
def ext_temp_dir(tmp_path_factory) -> Path:
    return Path(tmp_path_factory.mktemp("raw_data"))


@pytest.fixture
def gen_temp_dir(tmp_path_factory) -> Path:
    return Path(tmp_path_factory.mktemp("generated_data"))


def test_data_files(bin2ml_data_path, bin2ml_data):
    assert bin2ml_data_path.is_file()
    assert isinstance(bin2ml_data, dict) or isinstance(bin2ml_data, list)


def test_bin2ml_path():
    if not Path(BIN2ML_PATH).exists():
        pytest.skip(f"Bin2ML binary not found at {BIN2ML_PATH}.")
    result = subprocess.run([BIN2ML_PATH, "--version"], stdout=subprocess.PIPE)
    name = result.stdout.decode().split(" ")[0]
    assert name == "bin2ml"


def test_get_version(bin2ml):
    # Ensure commands through Bin2MLPipe work as expected
    version = bin2ml.get_version()
    version_pattern = re.compile(r"\d\.\d\.\d")
    
    assert isinstance(version, str)
    assert len(version) > 0
    assert version_pattern.match(version) is not None
    
    
def test_cmd(tmpdir, bin2ml, binary_path):
    result = bin2ml.cmd("extract", "--fpath", binary_path, "--output-dir",
                        tmpdir, "--modes", "cfg")
    assert result.stdout == b""

    # Test code mistake
    with pytest.raises(Bin2MLError):
        bin2ml.cmd("extract", "--fpath", binary_path)


def test_bulk_cmd(tmpdir, bin2ml, binary_path):
    result = bin2ml.cmd("extract", "--fpath", binary_path, "--output-dir",
                        tmpdir, "--modes", "cfg")
    assert result.stdout == b""


def test_extract(tmpdir, bin2ml, binary_path):
    bin2ml.extract(binary_path, tmpdir, "cfg", "--extended-analysis")
    bin2ml.extract(binary_path, tmpdir, "cg", "--debug", "--use-curl-pdb", 
                   "--with-annotations")
    bin2ml.extract(binary_path, tmpdir, ["reg", "finfo"], "--debug")
    extracted_files = list(Path(tmpdir).glob("*"))
    assert len(extracted_files) == 4
    
    
def test_extract_with_pattern(tmpdir, bin2ml, binaries_dir):
    bin_pattern = binaries_dir.joinpath("*")
    bin2ml.extract(bin_pattern, tmpdir, "cfg")
    cfg_pattern = Path(tmpdir).joinpath("*_cfg.json")
    bin2ml.generate_graphs(cfg_pattern, "cfg", tmpdir, "gemini")
    
    extracted_data = list(Path(tmpdir).glob("*"))
    assert len(extracted_data) == 8
    

@pytest.mark.parametrize("bin2ml_data_path", ["cfg"], indirect=True)
def test_generate_graphs(bin2ml, gen_temp_dir, bin2ml_data_path):
    if not bin2ml_data_path.exists():
        pytest.skip(f"Test data not found: {bin2ml_data_path}")
    bin2ml.generate_graphs(bin2ml_data_path, "cfg", gen_temp_dir, "gemini")
    generated_dirs = list(Path(gen_temp_dir).glob("*gemini"))
    
    assert len(generated_dirs) == 1
    assert generated_dirs[0].is_dir()
    assert len(list(generated_dirs[0].glob("*.json"))) > 0
    

@pytest.mark.parametrize("bin2ml_data_path", ["cfg"], indirect=True)
def test_generate_nlp(bin2ml, gen_temp_dir, bin2ml_data_path):
    if not bin2ml_data_path.exists():
        pytest.skip(f"Test data not found: {bin2ml_data_path}")
    bin2ml.generate_nlp(bin2ml_data_path, "esil", gen_temp_dir, "single")

    generated_nlps = list(Path(gen_temp_dir).glob("*"))
    
    assert len(generated_nlps) == 1
    
def test_binary_data_tracker(bin2ml, binary_path, tmpdir):
    tracker = BinaryDataTracker(binary_path, tmpdir)
    bin2ml.extract(binary_path, tmpdir, 
                   ["cfg", "func-cfg", "bytes"], 
                   "--extended-analysis")
    
    cfg_data_path = tracker.get_extract_path("cfg")
    func_cfg_data_path = tracker.get_extract_path("func-cfg")
    bytes_data_path = tracker.get_extract_path("bytes")
    assert cfg_data_path.is_file()
    assert func_cfg_data_path.is_dir()
    assert bytes_data_path.is_dir()
    assert len(list(func_cfg_data_path.glob("*.json"))) > 0
    assert len(list(bytes_data_path.glob("*.bin"))) > 0
    
    entry0_data_path = tracker.get_extract_path("func-cfg", 
                                                function_name="entry0")
    assert entry0_data_path.is_file()
    
    bin2ml.generate_graphs(cfg_data_path, "cfg", tmpdir, "gemini")
    gemini_data_path = tracker.get_generate_path(
        "cfg", "gemini", "fcn.140001a00")
    assert gemini_data_path.is_file()
