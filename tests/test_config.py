from pathlib import Path

import yaml

from binrankbench.common import config as config_module


def write_config(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_load_config_defaults(tmp_path, monkeypatch):
    config_module.reset_cache()
    monkeypatch.delenv(config_module.ENV_CONFIG_PATH, raising=False)
    config = config_module.load_config(tmp_path / "missing.yml")
    assert config.generator["n_runners"] == 4
    assert config.dashboard["enabled"] is True


def test_load_config_overrides(tmp_path, monkeypatch):
    config_module.reset_cache()
    custom_path = tmp_path / "configuration.yml"
    overrides = {
        "generator": {"n_runners": 8, "overwrite": True},
        "logging": {"default_level": "DEBUG", "components": {"main": "WARNING"}},
        "dashboard": {"enabled": False, "log_lines": 5},
    }
    write_config(custom_path, overrides)

    config = config_module.load_config(custom_path)
    assert config.generator["n_runners"] == 8
    assert config.generator["overwrite"] is True
    assert config.logging_level("main") == "WARNING"
    assert config.is_dashboard_enabled() is False
    assert config.dashboard["log_lines"] == 5


def test_force_reload_reads_updates(tmp_path, monkeypatch):
    config_module.reset_cache()
    config_path = tmp_path / "config.yml"
    write_config(config_path, {"generator": {"n_posters": 2}})

    cfg = config_module.load_config(config_path)
    assert cfg.generator["n_posters"] == 2

    # Modify file after initial load; without force reload we expect cached values
    write_config(config_path, {"generator": {"n_posters": 5}})
    cfg_cached = config_module.load_config(config_path)
    assert cfg_cached.generator["n_posters"] == 2

    cfg_reloaded = config_module.load_config(config_path, force_reload=True)
    assert cfg_reloaded.generator["n_posters"] == 5

