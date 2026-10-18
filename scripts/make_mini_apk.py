# -*- coding: utf-8 -*-
"""生成用于 CI 与自检的迷你 APK 固件 tests/fixtures/mini.apk。

背景：testSample/ 不入库，CI 上没有真实样本，打包产物的
`WinApkInfo.exe --self-test` 只能验证 aapt2 与随包资源，图标提取链路
（badging → 自适应图标 → 矢量栅格化）从未在 CI 上被真正走到。
本脚本只用随包的 aapt2 + Pillow 生成一个可入库的迷你 APK：

1. 先链接一个"框架桩"：用 public.xml + --allow-reserved-package-id 在
   android 包下固定 AOSP 公开属性 ID（versionCode/icon/...）；
2. 再以该桩作为 aapt2 link 的 -I 参数链接真正的应用 APK。

因此生成过程不依赖 android.jar 或本机 Android SDK。

用法（在仓库根目录）：
    python scripts/make_mini_apk.py                  # 写入默认路径
    python scripts/make_mini_apk.py -o out.apk       # 指定输出
    python scripts/make_mini_apk.py --aapt2 <path>   # 指定 aapt2
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_OUTPUT = ROOT / "tests" / "fixtures" / "mini.apk"

# AOSP public-final.xml 中的公开属性 ID：badging 的语义字段
# （versionCode / icon / label）依赖真实 ID，必须逐一保持一致。
_FRAMEWORK_ATTRS = (
    # (name, format, id)
    ("label", "string|reference", "0x01010001"),
    ("icon", "reference", "0x01010002"),
    ("height", "dimension", "0x01010155"),
    ("width", "dimension", "0x01010159"),
    ("drawable", "color|reference", "0x01010199"),
    ("color", "color|reference", "0x010101a5"),
    ("minSdkVersion", "integer", "0x0101020c"),
    ("versionCode", "integer", "0x0101021b"),
    ("versionName", "string", "0x0101021c"),
    ("targetSdkVersion", "integer", "0x01010270"),
    ("alpha", "float", "0x0101031f"),
    ("viewportWidth", "float", "0x01010402"),
    ("viewportHeight", "float", "0x01010403"),
    ("fillColor", "color|reference", "0x01010404"),
    ("pathData", "string", "0x01010405"),
    ("strokeColor", "color|reference", "0x01010406"),
    ("strokeWidth", "dimension", "0x01010407"),
    ("fillType", "integer", "0x0101051e"),
)

_STUB_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android"/>\n'
)

_APP_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.miniapk"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <application android:label="Mini APK" android:icon="@mipmap/ic_launcher" />
</manifest>
"""

_ADAPTIVE_ICON = """<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
</adaptive-icon>
"""

_FOREGROUND_VECTOR = """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M54,20 C72.8,20 88,35.2 88,54 C88,72.8 72.8,88 54,88 C35.2,88 20,72.8 20,54 C20,35.2 35.2,20 54,20 Z" />
</vector>
"""

_COLORS = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<resources><color name="ic_launcher_background">#3DDC84</color></resources>\n')


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(
            "命令失败（退出码 %d）：%s\n%s%s" % (
                proc.returncode, " ".join(str(c) for c in cmd),
                proc.stdout or "", proc.stderr or ""))


def _find_aapt2(explicit=None):
    if explicit:
        return explicit
    try:
        from core.aapt import find_aapt2
        return find_aapt2()
    except Exception:
        bundled = ROOT / "tools" / "aapt2.exe"
        if bundled.is_file():
            return str(bundled)
    raise SystemExit("未找到 aapt2：请放到 tools/aapt2.exe、加入 PATH 或用 --aapt2 指定")


def _write_stub(work: Path, aapt2: str):
    """生成框架桩 APK，返回其路径。"""
    stub_manifest = work / "stub" / "AndroidManifest.xml"
    stub_manifest.parent.mkdir(parents=True)
    stub_manifest.write_text(_STUB_MANIFEST, encoding="utf-8")

    values = stub_manifest.parent / "res" / "values"
    values.mkdir(parents=True)
    attrs = "\n".join(
        '    <attr name="%s" format="%s" />' % (name, fmt)
        for name, fmt, _ in _FRAMEWORK_ATTRS)
    (values / "attrs.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n%s\n</resources>\n' % attrs,
        encoding="utf-8")
    public = "\n".join(
        '    <public type="attr" name="%s" id="%s" />' % (name, rid)
        for name, _, rid in _FRAMEWORK_ATTRS)
    (values / "public.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n%s\n</resources>\n' % public,
        encoding="utf-8")

    compiled = work / "stub-compiled.zip"
    _run([aapt2, "compile", "--dir", str(stub_manifest.parent / "res"), "-o", str(compiled)])
    stub_apk = work / "framework-stub.apk"
    _run([aapt2, "link", "-o", str(stub_apk),
          "--manifest", str(stub_manifest),
          "--allow-reserved-package-id",
          "--min-sdk-version", "21",
          str(compiled)])
    return stub_apk


def _make_icon_png(path: Path, size: int, color):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = size // 8
    draw.ellipse([margin, margin, size - margin, size - margin], fill=color)
    img.save(path)


def _write_app(work: Path):
    """生成迷你应用工程（清单 + 资源），返回工程根目录。"""
    app = work / "app"
    res = app / "res"
    for sub in ("mipmap-hdpi", "mipmap-xxxhdpi", "mipmap-anydpi-v26", "drawable", "values"):
        (res / sub).mkdir(parents=True)

    (app / "AndroidManifest.xml").write_text(_APP_MANIFEST, encoding="utf-8")
    _make_icon_png(res / "mipmap-hdpi" / "ic_launcher.png", 72, (255, 64, 64, 255))
    _make_icon_png(res / "mipmap-xxxhdpi" / "ic_launcher.png", 192, (255, 64, 64, 255))
    (res / "mipmap-anydpi-v26" / "ic_launcher.xml").write_text(_ADAPTIVE_ICON, encoding="utf-8")
    (res / "drawable" / "ic_launcher_foreground.xml").write_text(_FOREGROUND_VECTOR, encoding="utf-8")
    (res / "values" / "colors.xml").write_text(_COLORS, encoding="utf-8")
    return app


def build(aapt2: str, output: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="winapkinfo-mini-") as tmp:
        work = Path(tmp)
        stub_apk = _write_stub(work, aapt2)
        app = _write_app(work)
        compiled = work / "app-compiled.zip"
        _run([aapt2, "compile", "--dir", str(app / "res"), "-o", str(compiled)])
        apk = work / "mini.apk"
        _run([aapt2, "link", "-o", str(apk),
              "--manifest", str(app / "AndroidManifest.xml"),
              "-I", str(stub_apk),
              str(compiled)])

        # 固件必须自带图标，否则 --self-test 的图标链路仍然跑不到
        badging = _dump_badging(aapt2, apk)
        if "application-icon-" not in badging:
            raise SystemExit("生成的 APK 缺少 application-icon 条目：\n" + badging)
        with zipfile.ZipFile(apk) as zf:
            names = set(zf.namelist())
        for rel in ("res/mipmap-anydpi-v26/ic_launcher.xml",
                    "res/drawable/ic_launcher_foreground.xml"):
            if rel not in names:
                raise SystemExit("生成的 APK 缺少资源：%s" % rel)

        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(apk, output)
    return output


def _dump_badging(aapt2: str, apk: Path) -> str:
    proc = subprocess.run([aapt2, "dump", "badging", str(apk)],
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return (proc.stdout or "") + (proc.stderr or "")


def main(argv=None):
    parser = argparse.ArgumentParser(description="生成 CI 用的迷你 APK 固件")
    parser.add_argument("output", nargs="?", default=str(DEFAULT_OUTPUT), help="输出 APK 路径")
    parser.add_argument("--aapt2", default="", help="aapt2 可执行文件路径")
    args = parser.parse_args(argv)

    aapt2 = _find_aapt2(args.aapt2 or None)
    output = build(aapt2, Path(args.output))
    print("aapt2 : %s" % aapt2)
    print("fixture: %s (%d 字节)" % (output, output.stat().st_size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
