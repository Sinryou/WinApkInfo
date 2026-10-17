# -*- coding: utf-8 -*-
"""生成 PyInstaller 使用的 Windows 版本资源文件。

用法：
    python scripts/gen_version_info.py 1.1.2 build/version_info.txt
"""
import re
import sys
from pathlib import Path


def parse_version(version: str):
    """把 1.1.2 / 1.1.2.0 解析成 Windows 需要的四段整数。"""
    parts = [int(x) for x in re.findall(r"\d+", version)[:4]]
    if not parts:
        raise ValueError("版本号必须包含数字：" + repr(version))
    return tuple((parts + [0, 0, 0, 0])[:4])


def render(version: str) -> str:
    filevers = parse_version(version)
    return f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={filevers},
    prodvers={filevers},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'Sinryou'),
         StringStruct('FileDescription', 'WinApkInfo - APK Info Viewer'),
         StringStruct('FileVersion', '{version}'),
         StringStruct('InternalName', 'WinApkInfo'),
         StringStruct('LegalCopyright', 'Copyright (c) 2025-2026 Sinryou. MIT License.'),
         StringStruct('OriginalFilename', 'WinApkInfo.exe'),
         StringStruct('ProductName', 'WinApkInfo'),
         StringStruct('ProductVersion', '{version}')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main(argv):
    if len(argv) != 3:
        print("usage: gen_version_info.py <version> <output.txt>", file=sys.stderr)
        return 2
    version, output = argv[1], Path(argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(version), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
