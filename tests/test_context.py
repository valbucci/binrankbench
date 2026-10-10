import binrankbench.common.context as ctx


def test_context():
    assert ctx.PKG_DIR.is_dir()
    assert ctx.ROOT_DIR.is_dir()
    assert ctx.THIRD_PARTY_DIR.is_dir()

    pyproject_toml_file = ctx.ROOT_DIR / "pyproject.toml"
    assert pyproject_toml_file.is_file()
