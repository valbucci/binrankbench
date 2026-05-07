"""Configuration management for binrankbench.

This module loads the project-wide ``configuration.yml`` file and exposes a
lightweight API for retrieving typed settings with sensible defaults.  Command
line entrypoints can override individual values after loading the configuration
object.
"""

from __future__ import annotations

import os
import re
import threading
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

import yaml
from dotenv import load_dotenv

from binrankbench.common.context import ROOT_DIR

# Load .env (if present) so POSTGRES_PASSWORD etc. are available for URL expansion.
load_dotenv(ROOT_DIR / ".env", override=False)

_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")

def _expand(s: str) -> str:
    """Expand ${VAR} and ${VAR:-default} placeholders using the current environment."""
    def _sub(m: re.Match) -> str:
        expr = m.group(1)
        if ":-" in expr:
            var, default = expr.split(":-", 1)
            return os.environ.get(var, default)
        return os.environ.get(expr, m.group(0))
    return _ENV_VAR_RE.sub(_sub, s)

DEFAULT_CONFIG_PATH = ROOT_DIR / "configuration.yml"
ENV_CONFIG_PATH = "BINRANKBENCH_CONFIG"

DEFAULT_CONFIG: Dict[str, Any] = {
    "generator": {
        "binaries_path": None,
        "raw_data_dir": None,
        "output_dir": None,
        "n_runners": 4,
        "n_posters": 1,
        "overwrite": False,
        "max_task_queue": 10000,
        "max_log_queue": 10000,
        "max_dashboard_log_queue": 2000,
    },
    "dashboard": {
        "enabled": True,
        "update_interval": 1.0,
        "refresh_per_second": 4.0,
        "log_lines": 20,
    },
    "logging": {
        "default_level": "INFO",
        "console_level": "INFO",
        "file_level": "WARNING",
        "components": {
            "main": "INFO",
            "TaskPoster": "INFO",
            "TaskRunner": "INFO",
            "ResultCollector": "INFO",
            "LoggingManager": "INFO",
            "dashboard": "INFO",
        },
    },
    "advanced": {
        "placeholder": None,
    },
    "storage": {
        "db_url": "postgresql+psycopg2://postgres:binrankbench@localhost:5432/binrankbench",
    },
}


def _deep_update(base: MutableMapping[str, Any], overrides: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in overrides.items():
        if (
            isinstance(value, Mapping)
            and key in base
            and isinstance(base[key], Mapping)
        ):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _resolve_config_path(path: Optional[Path]) -> Path:
    if path is not None:
        return path
    env_value = os.environ.get(ENV_CONFIG_PATH)
    if env_value:
        return Path(env_value).expanduser()
    return DEFAULT_CONFIG_PATH


_config_lock = threading.Lock()
_cached_path: Optional[Path] = None
_cached_config: Optional["Config"] = None


@dataclass(frozen=True)
class Config:
    """Wrapper providing convenient accessors for configuration sections."""

    data: Dict[str, Any]
    path: Path

    def get_section(self, name: str) -> Dict[str, Any]:
        return deepcopy(self.data.get(name, {}))

    @property
    def generator(self) -> Dict[str, Any]:
        return self.get_section("generator")

    @property
    def dashboard(self) -> Dict[str, Any]:
        return self.get_section("dashboard")

    @property
    def logging(self) -> Dict[str, Any]:
        return self.get_section("logging")

    @property
    def storage(self) -> Dict[str, Any]:
        return self.get_section("storage")

    def logging_level(self, component: str) -> str:
        components = self.logging.get("components", {})
        default_level = self.logging.get("default_level", "INFO")
        return str(components.get(component, default_level))

    def is_dashboard_enabled(self) -> bool:
        dash = self.dashboard
        return bool(dash.get("enabled", True))

    def get_console_level(self) -> str:
        """Get console log level from configuration."""
        return str(self.logging.get("console_level", "INFO"))

    def get_file_level(self) -> str:
        """Get file log level from configuration."""
        return str(self.logging.get("file_level", "WARNING"))


def load_config(path: Optional[Path] = None, force_reload: bool = False) -> Config:
    """Load configuration from YAML file, merging with defaults and caching."""

    resolved_path = _resolve_config_path(path)

    with _config_lock:
        global _cached_config, _cached_path
        if (
            not force_reload
            and _cached_config is not None
            and _cached_path == resolved_path
        ):
            return _cached_config

        config_data = deepcopy(DEFAULT_CONFIG)

        if resolved_path.exists():
            try:
                with resolved_path.open("r", encoding="utf-8") as fh:
                    loaded = yaml.safe_load(fh) or {}
                    if not isinstance(loaded, Mapping):
                        raise ValueError("configuration root must be a mapping")
                    _deep_update(config_data, loaded)
            except Exception as exc:
                raise RuntimeError(f"Failed to load configuration from {resolved_path}: {exc}") from exc

        # Expand ${VAR:-default} in the db_url so secrets live in .env, not YAML.
        if "storage" in config_data and "db_url" in config_data["storage"]:
            config_data["storage"]["db_url"] = _expand(config_data["storage"]["db_url"])

        config = Config(config_data, resolved_path)
        _cached_config = config
        _cached_path = resolved_path
        return config


def reset_cache() -> None:
    """Clear cached configuration (useful for tests)."""

    with _config_lock:
        global _cached_config, _cached_path
        _cached_config = None
        _cached_path = None
