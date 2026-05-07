import binrankbench.common.context as ctx


def test_context():
    assert ctx.PKG_DIR.is_dir()
    assert ctx.ROOT_DIR.is_dir()
    assert ctx.ASSETS_DIR.is_dir()
    
    pytest_ini_path = ctx.ROOT_DIR / "pytest.ini"
    assert pytest_ini_path.is_file()
