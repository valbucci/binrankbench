"""Python module to interact with bin2ml utility
https://github.com/br0kej/bin2ml
"""
import subprocess
import re
import logging

from pathlib import Path
from typing import Iterable, Literal, Any, Optional


# Compatible function file names templates
FuncFileTemplate = Literal["symbol", "address"] | str

# Compatible data extraction modes
ExtractMode = Literal[
    "finfo", "reg", "cfg", "func-cfg", "func-xrefs", "cg", "decomp",  
    "pcode-func", "pcode-bb", "localvar-xrefs", "strings", "bytes", 
    "bytes-masked", "fvars", "zigs", "bininfo"]
ExtractModeInput = ExtractMode | Iterable[ExtractMode]

# Compatible graphs generation modes
GraphData = Literal["cfg", "cg", "onehopcg", "cgcallers", "onehopcgcallers", 
                    "globalcg"]
GraphFeature = Literal["gemini", "discovre", "dgis", "tiknib", "disasm", "esil", 
                       "pcode", "pseudo"]

# Compatible NLP generation modes
NLPData = Literal["esil", "disasm", "pcode"]
NLPFormat = Literal["single", "funcstring"]
PCodeFormat = Literal["pcode-func", "pcode-bb"]

# Catch-all features
FeatureType = GraphFeature | NLPFormat


class Bin2MLError(Exception):
    pass


class BinaryDataTracker:
    
    LOGGER = logging.getLogger("BinaryDataTracker")
    EXTRACT_FORMAT = "{binary_name}_{data_type}{maybe_json_ext}"
    GENERATE_FORMAT = "{binary_name}_{data_type}-{feature_type}"
    FUNCTION_FORMAT = "{binary_name}_{data_type}-{function_name}{file_ext}"
    ERROR_FORMAT = "{binary_name}_{data_type}.error.log"
    
    def __init__(self, binary_path: Path | str, output_dir: Path | str):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        
    @property
    def binary_name(self) -> str:
        return self.binary_path.name
        
    @staticmethod
    def sanitize_filename(filename: str, max_length: int=100) -> str:
        # Replace non-valid characters with '_'
        # Valid characters: letters, digits, '_', '-', and '.'
        sanitized_name = re.sub(r"[^\w.-]", "_", filename)

        half_length = max_length // 2
        if len(sanitized_name) > max_length:
            sanitized_name = (sanitized_name[:half_length] + 
                              sanitized_name[-half_length:])

        return sanitized_name

    @staticmethod
    def get_file_extensions(data_type: ExtractMode
                            ) -> tuple[str, Optional[str]]:
        # If it's a folder with data files then we have None, file_ext
        extensions = {
            "bytes": ("", ".bin"),
            "bytes-masked": ("", ".masked.bin"),
            "func-cfg": ("", ".json"),
            # If it's a single file on extraction, but folder on generation
            # we specify two extensions
            "cfg": (".json", ".json"),
        }
        # If it's anything else then we have file_ext, None
        default = (".json", None)
        return extensions.get(data_type, default)
    
    @staticmethod
    def apply_function_file_template(template: FuncFileTemplate="symbol",
                                     function_name: Optional[str]=None,
                                     function_address: Optional[str]=None,
                                     func_file_ext: Optional[str]=None
                                     ) -> str:        
        file_name = None
        if template == "symbol":
            if function_name is None:
                raise ValueError(
                    "Function name is required when template is 'symbol'")
            file_name = (f"{function_name}{func_file_ext}" 
                         if func_file_ext is not None else function_name)
            
        elif template == "address":
            if function_address is None:
                raise ValueError(
                    "Function address is required when template is 'address'")
            file_name = (f"{function_address}{func_file_ext}" 
                         if func_file_ext is not None else function_address)
            
        else:
            # Template will look like "{address}-{symbol}.{ext}"
            # Check any of these are in the template and make sure the
            # corresponding arguments are not None
            if not ("{address}" in template or "{symbol}" in template):
                raise ValueError("Template must contain '{address}' "
                                 "or '{symbol}'")
            elif "{address}" in template and function_address is None:
                raise ValueError("Function address is required when template "
                                 "contains '{address}'")
            elif "{symbol}" in template and function_name is None:
                raise ValueError("Function name is required when template "
                                 "contains '{symbol}'")

            file_name = template.format(address=function_address, 
                                        symbol=function_name,
                                        ext=func_file_ext)
        
        return file_name
        
    def get_function_file_name(self, data_type: ExtractMode,
                               template: FuncFileTemplate="symbol",
                               function_name: Optional[str] = None,
                               function_address: Optional[str] = None) -> str:
        _, func_file_ext = self.get_file_extensions(data_type)
        if func_file_ext is None:
            self.LOGGER.debug("Using default function file extension for "
                              f"{data_type} data type")
            func_file_ext = ".json"
            
        file_name = self.apply_function_file_template(template, function_name, 
                                                      function_address,
                                                      func_file_ext)
        return self.sanitize_filename(file_name)
        
    def get_extract_path(self, data_type: ExtractMode,
                         template: FuncFileTemplate="symbol",
                         function_name: Optional[str] = None,
                         function_address: Optional[str] = None) -> Path:
        bin_ext, _ = self.get_file_extensions(data_type)
        if bin_ext is None:
            # Replace empty bin_ext with empty string
            bin_ext = ""
            
        extract_name = self.EXTRACT_FORMAT.format(
            binary_name=self.binary_name, data_type=data_type, 
            maybe_json_ext=bin_ext)
        extract_path = self.output_dir.joinpath(extract_name)
        
        if function_name is None and function_address is None:
            return extract_path
        else:
            file_name = self.get_function_file_name(data_type, template, 
                                                    function_name, 
                                                    function_address)
            return extract_path.joinpath(file_name)
        
    def get_extract_paths(self, modes: ExtractModeInput
                          ) -> dict[ExtractMode, Path]:
        return {mode: self.get_extract_path(mode) for mode in 
                Bin2MLPipe.get_modes_list(modes)}
        
    def get_error_path(self, data_type: ExtractMode, 
                       function_name: Optional[str] = None) -> Path:
        error_name = self.ERROR_FORMAT.format(
            binary_name=self.binary_name, data_type=data_type)
        
        return self.output_dir.joinpath(error_name)
    
    def get_error_paths(self, modes: ExtractModeInput
                        ) -> dict[ExtractMode, Path]:
        return {mode: self.get_error_path(mode) for mode in 
                Bin2MLPipe.get_modes_list(modes)}
    
    def get_generate_path(self, data_type: ExtractMode, 
                          feature_type: FeatureType, 
                          function_name: Optional[str] = None) -> Path:
        generate_dir_name = self.GENERATE_FORMAT.format(
            binary_name=self.binary_name, data_type=data_type, 
            feature_type=feature_type)
        generate_dir_path = self.output_dir.joinpath(generate_dir_name)
        if function_name is None:
            return generate_dir_path
        else:
            # This will need more flexible handling in the future
            func_file_ext = ".json"
            file_name = self.FUNCTION_FORMAT.format(
                binary_name=self.binary_name, data_type=data_type, 
                function_name=function_name, file_ext=func_file_ext)
            return generate_dir_path.joinpath(file_name)


class Bin2MLPipe:
    
    def __init__(self, exe_path: str | Path, num_threads=2, capture_output: bool = True):
        self.validate_bin2ml_path(Path(exe_path))
        self.exe_path = str(exe_path)
        self._num_threads = num_threads
        self._capture_output = capture_output
        
    @staticmethod
    def get_modes_list(modes: ExtractModeInput) -> list[ExtractMode]:
        if isinstance(modes, str):
            return [modes]
        else:
            return list(modes)
        
    def extract(self, input_path: Path | str, output_dir: Path | str, 
                modes: ExtractModeInput, *options: Any
                ) -> subprocess.CompletedProcess:
        modes = self.get_modes_list(modes)
        return self.cmd("extract", *options, "-f", input_path, 
                        "-o", output_dir, "-m", *modes, "-n", self._num_threads)
        
    def generate_graphs(self, data_path: Path | str, data_type: GraphData, 
                        output_dir: Path | str, feature_type: GraphFeature,
                        *options: Any) -> subprocess.CompletedProcess:
        return self.cmd(
            "generate", "graphs", *options, "-p", data_path,
            "-d", data_type, "-o", output_dir, "-f", feature_type, 
            "-n", self._num_threads)
        
    def generate_nlp(self, data_path: Path | str, data_type: NLPData, 
                     output_dir: Path | str, feature_type: NLPFormat, 
                     *options: Any, pcode_format: Optional[PCodeFormat]=None
                     ) -> subprocess.CompletedProcess:
        _options = list(options)
        if pcode_format is not None:
            _options.extend(["--pcode-file-format", pcode_format])
        return self.cmd("generate", "nlp", *_options, "-p", data_path, 
                        "-i", data_type, "-d", output_dir, "-o", feature_type)
    
    @staticmethod
    def validate_bin2ml_path(bin2ml_path: Path):
        if not bin2ml_path.exists():
            raise FileNotFoundError(
                f"The provided Bin2ML path {bin2ml_path} does not exist.")
        elif not bin2ml_path.is_file():
            raise FileNotFoundError(
                f"The provided Bin2ML path {bin2ml_path} is not a file.")
    
    def cmd(self, *args, capture_output: bool | None = None) -> subprocess.CompletedProcess:
        if capture_output is None:
            capture_output = self._capture_output
        command = list(map(str, (self.exe_path, *args)))
        result = subprocess.run(command, capture_output=capture_output)
        if result.returncode != 0:
            command_str = " ".join(command)
            stderr = result.stderr.decode() if result.stderr else "(output not captured)"
            raise Bin2MLError("Encountered Bin2ML error when executing:\n"
                              f"{command_str!r}:\n{stderr}")
        return result

    def get_version(self):
        return self.cmd("--version", capture_output=True).stdout.decode().split(" ")[-1]
