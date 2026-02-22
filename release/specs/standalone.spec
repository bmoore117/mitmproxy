# -*- mode: python ; coding: utf-8 -*-

for tool in ["mitmproxy", "mitmdump", "mitmweb"]:
    excludes = []
    if tool != "mitmweb":
        excludes.append("mitmproxy.tools.web")
    if tool != "mitmproxy":
        excludes.append("mitmproxy.tools.console")

    options = []
    if tool == "mitmdump":
        # https://github.com/mitmproxy/mitmproxy/issues/6757
        options.append(("unbuffered", None, "OPTION"))

    # Addon dependencies not transitively imported by mitmproxy itself
    addon_hiddenimports = [
        'lxml', 'lxml.etree', 'lxml.html',
        'ahocorasick',
        'bs4',
        'watchdog', 'watchdog.events', 'watchdog.observers',
        'wsproto', 'wsproto.frame_protocol',
    ]

    a = Analysis(
        [tool],
        excludes=excludes,
        hiddenimports=addon_hiddenimports,
    )
    pyz = PYZ(a.pure, a.zipped_data)

    EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        options,
        name=tool,
        console=True,
        icon="icon.ico",
    )
