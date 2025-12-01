# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['webserver.py'],
    pathex=[],
    binaries=[
        ('/home/admin/Diplom/Diplom/venv/lib64/python3.11/site-packages/pyescrypt','pyescrypt'),
    ],
    datas=[
        ('/home/admin/Diplom/Diplom/templates','templates'),
        ('/home/admin/Diplom/Diplom/gost_tables', '.'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onefile=True,
)

