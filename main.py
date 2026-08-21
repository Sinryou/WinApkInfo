# -*- coding: utf-8 -*-
import os
import sys
import re
import io
import math
import tempfile
import shutil
import subprocess
import json
import logging
import threading
from pathlib import Path
import zipfile
from PIL import Image, ImageChops, ImageDraw

try:
    import numpy as np
except ImportError:  # numpy 可选：缺失时栅格化回退纯 Python 实现
    np = None

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QLabel


# subprocess.CREATE_NO_WINDOW 仅存在于 Windows；macOS/Linux 上访问会在运行时报
# AttributeError。此处按平台解析为固定常量，跨平台安全（非 Windows 传 0 即可）。
if sys.platform == "win32":
    _SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _SUBPROCESS_FLAGS = 0


class Aapt2Error(RuntimeError):
    """aapt2 执行失败（非零退出），message 为解码后的 stderr/stdout 文本。"""


def _decode_output(data: bytes) -> str:
    """按严格优先级解码 aapt2 输出：utf-8-sig → gbk → cp936，最后宽松兜底。

    utf-8-sig 必须排在 utf-8 前面：`bytes.decode("utf-8")` 不会剥离 BOM
    （会把 U+FEFF 留在字符串开头），utf-8-sig 则同时兼容带/不带 BOM 的
    UTF-8 文本。旧实现用 errors="ignore" 逐个尝试，decode 永不抛异常，
    回退链实际是死代码；严格解码才能让回退真正生效。
    """
    for enc in ("utf-8-sig", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class _Aapt2OutputCache:
    """按 (apk 路径, mtime_ns, 子命令, 参数) 缓存 aapt2 dump 输出。

    图标解析链路会对同一 APK 反复执行 dump（每个 XML 层一次 xmltree、
    full_res 缺省时多次 resources），缓存可避免重复起子进程。
    键含 mtime，APK 被替换后自动失效；有界容量 + 线程锁。
    """

    def __init__(self, capacity=32):
        self._capacity = capacity
        self._cache = {}
        self._order = []
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            return self._cache.get(key)

    def put(self, key, value):
        with self._lock:
            if key not in self._cache:
                self._order.append(key)
            self._cache[key] = value
            while len(self._order) > self._capacity:
                old = self._order.pop(0)
                self._cache.pop(old, None)


_aapt2_cache = _Aapt2OutputCache()


def _aapt2_cache_key(apk_path: str, kind: str, arg=None):
    mtime = os.stat(apk_path).st_mtime_ns
    return (os.path.abspath(apk_path), mtime, kind, arg)


def local_resource_path(relative_path):
    """兼容打包前后路径"""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.argv[0])))
    return os.path.join(base_path, relative_path)

_sdk_versions_cache = None

def load_sdk_versions():
    """尝试读取 resources/android_sdk_versions.json（结果缓存，失败也缓存空表）。"""
    global _sdk_versions_cache
    if _sdk_versions_cache is not None:
        return _sdk_versions_cache
    sdk_map = {}
    # here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    # sdk_file = here / "android_sdk_versions.json"
    sdk_file = Path(local_resource_path("resources/android_sdk_versions.json"))
    if not sdk_file.exists():
        _sdk_versions_cache = sdk_map
        return sdk_map
    try:
        with open(sdk_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 建立 {apiLevel: (版本, codename)} 映射
        for item in data:
            api = str(item.get("apiLevel"))
            version = item.get("version", "")
            codename = item.get("codename") or ""
            # 去掉"Android "前缀
            if version.startswith("Android "):
                version = version.replace("Android ", "", 1)
            # codename 去空格
            codename = codename.replace(" ", "") if codename else ""
            # 拼接成 "8.0 Pie" 或 "14 UpsideDownCake"
            if codename:
                sdk_map[api] = f"{version} {codename}"
            else:
                sdk_map[api] = version
        _sdk_versions_cache = sdk_map
    except Exception as e:
        logging.warning("读取 android_sdk_versions.json 出错: %s", e)
        _sdk_versions_cache = sdk_map
    return sdk_map

def find_aapt2() -> str:
    """
    优先在脚本同级目录查找 aapt2 / aapt2.exe；否则使用系统 PATH 中的 aapt2。
    找不到则抛出 FileNotFoundError。
    """
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # 支持 PyInstaller
    candidates = [here / "aapt2", here / "aapt2.exe", here / "tools" / "aapt2.exe"]
    for c in candidates:
        if c.exists() and os.access(str(c), os.X_OK):
            return str(c)

    sys_aapt2 = shutil.which("aapt2")
    if sys_aapt2:
        return sys_aapt2

    raise FileNotFoundError("未找到 aapt2，请将 aapt2 放到脚本同级目录或加入系统 PATH。")


def run_aapt2_dump_badging(apk_path: str) -> str:
    """
    运行 `aapt2 dump badging "<apk>"` 并返回 stdout 文本。
    非零退出时抛出 Aapt2Error（含解码后的 stderr），不再把错误当正常输出返回。
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "badging", apk_path]

    key = _aapt2_cache_key(apk_path, "badging")
    cached = _aapt2_cache.get(key)
    if cached is not None:
        return cached

    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_SUBPROCESS_FLAGS
    )
    if proc.returncode != 0:
        err = (_decode_output(proc.stderr or proc.stdout)).strip() or f"aapt2 退出码 {proc.returncode}"
        raise Aapt2Error(err)

    text = _decode_output(proc.stdout)
    _aapt2_cache.put(key, text)
    return text

def run_aapt2_dump_resource(apk_path: str) -> str:
    """
    运行 `aapt2 dump resources "<apk>"` 并返回完整 stdout 文本。

    注意：这里返回全量输出而不是按地址截取的上下文窗口。旧实现用「±10 行」的
    模糊窗口去匹配 `resource {id} (.*?)resource 0x`，当目标条目恰好是资源表
    最后一条（后面没有下一个 `resource 0x`）或条目密度变体超过 10 行时，
    窗口里取不到终止符/完整内容，会误判为 unknown。全量输出交给
    extract_resource_entry 做精确、无歧义的条目截取。
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "resources", apk_path]

    key = _aapt2_cache_key(apk_path, "resources")
    cached = _aapt2_cache.get(key)
    if cached is not None:
        return cached

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_SUBPROCESS_FLAGS)
    if proc.returncode != 0:
        # 图标链路保持宽松：dump 失败时返回错误文本，由上层走位图回退
        return _decode_output(proc.stderr or proc.stdout)

    text = _decode_output(proc.stdout)
    _aapt2_cache.put(key, text)
    return text


def _entry_span(lines, start):
    """返回资源条目 [start, end) 行区间：到下一个 `resource 0x` 或 `type ... id=` 分节行前。"""
    end = start + 1
    while end < len(lines):
        s = lines[end].strip()
        if s.startswith("resource 0x") or re.match(r"^type\s+\w+\s+id=", s):
            break
        end += 1
    return start, end


class _ResourceIndex:
    """一次性解析 `aapt2 dump resources` 全量输出，提供 O(1) 的条目查询。

    图标解析链路会对同一份全量输出做多次线性扫描（每个资源 id 一次、
    每条文件路径一次），对大型 APK 是全量文本的重复开销。
    """

    __slots__ = ("by_id", "by_file")

    def __init__(self, full_output: str):
        self.by_id = {}
        self.by_file = {}
        lines = (full_output or "").splitlines()
        n = len(lines)
        i = 0
        while i < n:
            m = re.match(r"resource\s+(0x[0-9a-fA-F]+)(?:\s+\S+)?", lines[i].strip())
            if not m:
                i += 1
                continue
            rid = m.group(1).lower()
            a, b = _entry_span(lines, i)
            entry = "\n".join(lines[a:b])
            self.by_id[rid] = entry
            for line in lines[a:b]:
                fm = re.match(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+)", line)
                if fm:
                    self.by_file.setdefault(fm.group(2), entry)
            i = b


def extract_resource_entry(full_output: str, res_id: str, index=None) -> str:
    """
    从 `aapt2 dump resources` 全量输出中精确截取某个资源条目。

    条目以 `resource 0x{id} <pkg>/<name>` 行开始，到下一个 `resource 0x` 行
    或 `type <type> id=..` 分节行之前结束（含其所有密度变体行）。
    找不到返回空字符串。传入 index（_ResourceIndex）时 O(1) 查询。
    """
    if index is not None:
        return index.by_id.get(res_id.lower(), "")

    lines = full_output.splitlines()
    rid = res_id.lower()
    start = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("resource ") and s.split()[1].lower() == rid:
            start = i
            break
    if start is None:
        return ""

    a, b = _entry_span(lines, start)
    return "\n".join(lines[a:b])

def run_aapt2_dump_xmltree(apk_path: str, inner_file_path: str) -> str:
    """
    运行 `aapt2 dump xmltree "<apk>"` 并返回 stdout 文本。
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "xmltree", apk_path, "--file", inner_file_path]

    key = _aapt2_cache_key(apk_path, "xmltree", inner_file_path)
    cached = _aapt2_cache.get(key)
    if cached is not None:
        return cached

    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_SUBPROCESS_FLAGS
    )
    if proc.returncode != 0:
        # 图标链路保持宽松：dump 失败时返回错误文本，由上层走位图回退
        return _decode_output(proc.stderr or proc.stdout)

    text = _decode_output(proc.stdout)
    _aapt2_cache.put(key, text)
    return text

# ---------------- 资源条目解析 ----------------

# aapt2 dump resources 里「文件型」条目会标注 type=PNG / type=XML；
# 但 WebP 等位图不标注任何 type（形如 `(xxhdpi) (file) res/Sn.webp`），
# 所以位图识别必须按扩展名兜底，不能只看 type=PNG。
_BITMAP_EXTS = (".png", ".webp", ".jpg", ".jpeg", ".gif")
# 密度从低到高，用于在多个密度变体中挑选最高分辨率
_DPI_ORDER = ["ldpi", "mdpi", "tvdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]
# 混淆包中字符串引用/包装 XML 的最大解引用深度，防止循环引用
_MAX_DEREF_DEPTH = 3


def _density_of(qualifier: str) -> str:
    """从配置限定符中提取密度（如 "xxhdpi"、"anydpi-v26"、"hdpi-v25"）。"""
    m = re.search(r"(ldpi|mdpi|tvdpi|hdpi|xhdpi|xxhdpi|xxxhdpi|nodpi|anydpi)", qualifier or "")
    return m.group(1) if m else ""


def _pick_best_density(variants: dict):
    """variants: {density: path}，优先返回最高标准密度，其次 nodpi/默认，最后取末条。"""
    for dpi in reversed(_DPI_ORDER):
        if dpi in variants:
            return variants[dpi]
    for dpi in ("nodpi", ""):
        if dpi in variants:
            return variants[dpi]
    if variants:
        return next(reversed(variants.values()))
    return None


_sniff_cache = {}
_sniff_cache_lock = threading.Lock()


def _sniff_file_kind(apk_path: str, inner_path: str):
    """
    用魔数识别 APK 内文件类型（AndResGuard 等混淆后文件没有扩展名）。
    返回 "image" / "xml" / None。结果按 (apk 路径, mtime, 文件路径) 缓存，
    避免同一次提取链路里反复打开同一个 zip（不持有 ZipFile 句柄，
    以免影响 Windows 上的重命名操作）。
    """
    try:
        key = (os.path.abspath(apk_path), os.stat(apk_path).st_mtime_ns, inner_path)
    except OSError:
        return None
    with _sniff_cache_lock:
        if key in _sniff_cache:
            return _sniff_cache[key]
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            head = zf.open(inner_path).read(16)
    except Exception:
        return None
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        kind = "image"
    elif head[:4] == b"\x89PNG":
        kind = "image"
    elif head[:2] == b"\xff\xd8":
        kind = "image"
    elif head[:4] == b"GIF8":
        kind = "image"
    elif head[:4] == b"\x03\x00\x08\x00":  # Android 二进制 XML 头
        kind = "xml"
    else:
        kind = None
    with _sniff_cache_lock:
        if len(_sniff_cache) > 512:
            _sniff_cache.clear()
        _sniff_cache[key] = kind
    return kind


def get_resource_info(entry_text: str) -> dict:
    """
    解析一个 aapt2 dump resources 资源条目（extract_resource_entry 的返回值）。

    返回：
        dict: {
            "type": "color",       "value": "#AARRGGBB"
            "type": "image",       "value": 最高密度位图路径（png/webp/jpg/gif）
            "type": "vector",      "value": xml 路径（矢量 drawable，无法直接栅格化）
            "type": "string_file", "value": 指向文件的字符串值（混淆包），需进一步解析
            "type": "unknown",     "value": None
        }
    """
    lines = (entry_text or "").splitlines()

    bitmaps = {}        # density -> path
    xml_files = []      # path
    string_files = []   # (density, value)
    color = None

    file_re = re.compile(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+?)(?:\s+type=(\w+))?\s*$")
    str_re = re.compile(r"^\s*\(([^)]*)\)\s*\"([^\"]+)\"\s*$")
    color_re = re.compile(r"^\s*\(\s*\)\s*(#[0-9a-fA-F]{6,8})\s*$")

    for line in lines[1:]:  # 跳过 `resource 0x..` 头部行
        m = file_re.match(line)
        if m:
            qual, path, typ = m.group(1).strip(), m.group(2), m.group(3)
            if typ == "PNG" or path.lower().endswith(_BITMAP_EXTS):
                bitmaps[_density_of(qual)] = path
            else:
                xml_files.append(path)
            continue
        m = str_re.match(line)
        if m:
            string_files.append((m.group(1).strip(), m.group(2)))
            continue
        if color is None:
            m = color_re.match(line)
            if m:
                color = m.group(1)

    if bitmaps:
        return {"type": "image", "value": _pick_best_density(bitmaps)}
    if color:
        return {"type": "color", "value": color}
    if xml_files:
        return {"type": "vector", "value": xml_files[0]}
    if string_files:
        return {"type": "string_file", "value": string_files[0][1]}
    return {"type": "unknown", "value": None}


def find_adaptive_layer_addr(xml_output: str, layer: str):
    """
    从 `aapt2 dump xmltree` 输出中提取 adaptive-icon 的
    background / foreground 层引用的资源地址。

    兼容两种 aapt 输出格式：
        新版: A: ...:drawable(0x01010199)=@0x7f060000
        旧版: A: ...:drawable(0x01010199)=(type 0x01)0x7f060000
    找不到返回 None。
    """
    lines = (xml_output or "").splitlines()
    ref_re = re.compile(
        r"A: [^=\n]*?(\w+)\(0x[0-9a-fA-F]+\)\s*=\s*(?:\(type\s+0x01\)\s*)?@?(0x[0-9a-fA-F]+)"
    )
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)E:\s+" + re.escape(layer) + r"\s*\(", line)
        if not m:
            continue
        indent = len(m.group(1))
        for line2 in lines[i + 1:]:
            if not line2.strip():
                continue
            if len(line2) - len(line2.lstrip()) <= indent:
                break  # 已离开当前元素
            m2 = ref_re.search(line2)
            if m2 and m2.group(1) == "drawable":
                return m2.group(2)
        break
    return None


def _resolve_xml_wrapper(apk_path: str, full_res: str, xml_path: str, depth: int, index=None):
    """
    若 xml_path 指向 <scale>/<layer-list> 等包装 drawable，且其 android:drawable
    引用了另一个资源，则跟随引用继续解析（<scale> 的缩放参数一并带回）。
    根元素是纯 <vector> 或找不到引用时返回 (None, None, None)。
    """
    xml_out = run_aapt2_dump_xmltree(apk_path, xml_path)
    if not xml_out.strip():
        return (None, None, None)
    root_m = re.search(r"E:\s*(\S+)", xml_out)
    if root_m and root_m.group(1) == "vector":
        # 纯矢量 drawable：交由 rasterize_vector_layer 栅格化
        return ("vector", xml_path, None)
    m = re.search(
        r"A: [^=\n]*?drawable\(0x[0-9a-fA-F]+\)\s*=\s*(?:\(type\s+0x01\)\s*)?@?(0x[0-9a-fA-F]+)",
        xml_out,
    )
    if not m:
        return (None, None, None)
    scale = None
    sw = re.search(r"scaleWidth[^=\n]*=\s*\"([0-9]+(?:\.[0-9]+)?)%\"", xml_out)
    sh = re.search(r"scaleHeight[^=\n]*=\s*\"([0-9]+(?:\.[0-9]+)?)%\"", xml_out)
    sg = re.search(r"scaleGravity\([^)]*\)\s*=\s*(?:\(type\s+0x10\)\s*)?(0x[0-9a-fA-F]+)", xml_out)
    if sw or sh:
        scale = (
            float(sw.group(1)) if sw else 100.0,
            float(sh.group(1)) if sh else 100.0,
            int(sg.group(1), 16) if sg else 0x11,  # 默认居中
        )
    kind, value, scale2 = resolve_icon_layer(apk_path, full_res, m.group(1), depth + 1, index)
    if not kind:
        return (None, None, None)
    return (kind, value, scale or scale2)


def resolve_icon_layer(apk_path: str, full_res: str, res_id: str, depth: int = 0, index=None):
    """
    把一个图标层资源完整解析成可渲染形态：
        ("color", "#AARRGGBB", None)
        ("image", "res/...png", None)
        ("vector", "res/...xml", None)   # 纯矢量，无法栅格化
        (None, None, None)               # 无法解析
    scale 参数 (width%, height%, gravity) 来自 <scale> 包装。

    支持混淆包的解引用链：字符串值指向文件、无扩展名文件按魔数识别、
    <scale> 包装继续跟随 android:drawable 引用；深度受限防止循环。
    另外支持 Android 框架资源引用（0x01xxxxxx，如 @android:color/transparent）。
    index 为 _ResourceIndex 时条目查询 O(1)。
    """
    rid = (res_id or "").lower()
    if rid.startswith("0x01"):
        # 框架资源（android 包）：资源表里没有，走内置颜色表
        if rid in _FRAMEWORK_COLOR_MAP:
            return ("color", _FRAMEWORK_COLOR_MAP[rid], None)
        if rid.startswith("0x0106"):  # 框架 color 类型
            return ("color", "#00000000", None)  # 未知框架颜色按透明处理
        return (None, None, None)
    info = get_resource_info(extract_resource_entry(full_res, res_id, index))
    kind, value = info["type"], info["value"]
    if kind in ("color", "image"):
        return (kind, value, None)
    if depth >= _MAX_DEREF_DEPTH:
        return ("vector", value, None) if kind == "vector" else (None, None, None)
    if kind == "string_file":
        ext = os.path.splitext(value)[1].lower()
        if ext in _BITMAP_EXTS:
            return ("image", value, None)
        if ext == ".xml":
            return _resolve_xml_wrapper(apk_path, full_res, value, depth, index)
        sniffed = _sniff_file_kind(apk_path, value)
        if sniffed == "image":
            return ("image", value, None)
        if sniffed == "xml":
            return _resolve_xml_wrapper(apk_path, full_res, value, depth, index)
        return (None, None, None)
    if kind == "vector" and value:
        kind2, value2, scale2 = _resolve_xml_wrapper(apk_path, full_res, value, depth, index)
        if kind2:
            return (kind2, value2, scale2)
        return ("vector", value, None)
    return (None, None, None)


def _collect_bitmap_variants(entry_text: str) -> dict:
    """从资源条目文本收集 {density: 位图路径}。"""
    variants = {}
    for line in (entry_text or "").splitlines():
        m = re.match(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+)", line)
        if m and m.group(2).lower().endswith(_BITMAP_EXTS):
            variants[_density_of(m.group(1))] = m.group(2)
    return variants


def find_mipmap_fallback(full_res: str, icon_xml_path: str, index=None):
    """
    自适应图标（.xml）无法整体栅格化时的回退：
    找到包含该 icon xml 的资源条目（通常是 mipmap/ic_launcher），
    返回其最高密度的位图变体路径（即 8.0 之前使用的传统回退图标）。
    传入 index（_ResourceIndex）时 O(1) 查询。
    """
    if index is not None:
        entry = index.by_file.get(icon_xml_path)
        if entry is None:
            return None
        return _pick_best_density(_collect_bitmap_variants(entry))

    lines = full_res.splitlines()
    target = None
    for i, line in enumerate(lines):
        if f"(file) {icon_xml_path}" in line:
            target = i
            break
    if target is None:
        return None

    start = target
    while start > 0 and not lines[start - 1].strip().startswith("resource 0x"):
        start -= 1
    a, b = _entry_span(lines, start)
    return _pick_best_density(_collect_bitmap_variants("\n".join(lines[a:b])))

def parse_android_color(color_str: str):
    """
    把 Android 格式 #AARRGGBB 转成 Pillow 可用的 (R, G, B, A)
    """
    color_str = color_str.lstrip('#')
    if len(color_str) == 8:  # AARRGGBB
        a = int(color_str[0:2], 16)
        r = int(color_str[2:4], 16)
        g = int(color_str[4:6], 16)
        b = int(color_str[6:8], 16)
        return (r, g, b, a)
    elif len(color_str) == 6:  # RRGGBB
        r = int(color_str[0:2], 16)
        g = int(color_str[2:4], 16)
        b = int(color_str[4:6], 16)
        return (r, g, b, 255)
    else:
        raise ValueError("不合法的颜色格式: " + color_str)

# ---------------- Vector Drawable 栅格化 ----------------

# Android 框架（android 包）中常见的颜色资源，用于解析 0x01xxxxxx 引用
# （TS 等混淆包的自适应图标背景会直接引用 @android:color/transparent）
_FRAMEWORK_COLOR_MAP = {
    "0x0106000b": "#00000000",  # android:color/transparent
    "0x0106000c": "#ff000000",  # android:color/black
    "0x0106000d": "#ffffffff",  # android:color/white
    "0x0106000e": "#ff444444",  # android:color/darker_gray
    "0x0106000f": "#ff888888",  # android:color/gray
    "0x01060010": "#ffcccccc",  # android:color/lighter_gray
}

_VECTOR_CAPS = {"butt": 0, "round": 1, "square": 2, "0x00000000": 0, "0x00000001": 1, "0x00000002": 2}


def _parse_vector_elements(xml_out):
    """把 aapt2 dump xmltree 输出解析为 [{indent, tag, attrs}] 元素列表。"""
    elems = []
    for line in (xml_out or "").splitlines():
        m = re.match(r"^(\s*)E:\s+(\S+)\s*\(", line)
        if m:
            elems.append({"indent": len(m.group(1)), "tag": m.group(2), "attrs": {}})
            continue
        m = re.match(r"^(\s*)A:\s+[^=]*?(\w+)\(0x[0-9a-fA-F]+\)=(.*)$", line)
        if m and elems:
            name, raw = m.group(2), m.group(3).strip()
            if raw.startswith('"'):
                value = raw[1:raw.find('"', 1)]
            elif raw.startswith("'"):
                value = raw[1:raw.find("'", 1)]
            else:
                # 形如 108.000000dp / 30% / #aarrggbb / 0x00000011
                value = raw.split(" ", 1)[0].split("(", 1)[0]
            elems[-1]["attrs"][name] = value
    return elems


def _attr_float(attrs, name, default=None):
    v = attrs.get(name)
    if v is None:
        return default
    m = re.match(r"^([-+0-9.eE]+)", v)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return default
    return default


def _tokenize_path_data(d):
    """SVG pathData 词法切分，返回 [(cmd, 0.0) | (None, float)] 序列。"""
    tokens = []
    i, n = 0, len(d)
    while i < n:
        c = d[i]
        if c in " \t\r\n,":
            i += 1
            continue
        if c in "MmZzLlHhVvCcSsQqTtAa":
            tokens.append((c, 0.0))
            i += 1
            continue
        if c.isdigit() or c in "+-.":
            j = i + (1 if c in "+-." else 0)
            while j < n and (d[j].isdigit() or d[j] == "."):
                j += 1
            if j < n and d[j] in "eE":
                k = j + 1
                if k < n and d[k] in "+-":
                    k += 1
                if k < n and d[k].isdigit():
                    j = k
                    while j < n and d[j].isdigit():
                        j += 1
            tokens.append((None, float(d[i:j])))
            i = j
            continue
        i += 1
    return tokens


_ARITY = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}


def _parse_path_commands(tokens):
    """把 tokens 解析为 [(cmd, [args])] 命令列表（展开隐式重复参数）。"""
    cmds = []
    i, n = 0, len(tokens)
    while i < n:
        if tokens[i][0] is None:
            i += 1
            continue
        cmd = tokens[i][0]
        i += 1
        if cmd in "Zz":
            cmds.append(("Z", []))
            continue
        nargs = _ARITY[cmd.upper()]
        first = []
        while i < n and len(first) < nargs and tokens[i][0] is None:
            first.append(tokens[i][1])
            i += 1
        if len(first) < nargs:
            continue
        cmds.append((cmd, first))
        if nargs == 0:
            continue
        # 隐式重复：后续相同参数个数的数字串（M/m 的额外对子按隐式 L/l 处理）
        while i < n and tokens[i][0] is None:
            args = []
            while i < n and len(args) < nargs and tokens[i][0] is None:
                args.append(tokens[i][1])
                i += 1
            if len(args) < nargs:
                break
            next_cmd = cmd
            if cmd in "Mm":
                next_cmd = "L" if cmd == "M" else "l"
            cmds.append((next_cmd, args))
    return cmds


def _bezier_points(p0, p1, p2, p3, step):
    ext = max(abs(p1[0] - p0[0]), abs(p2[0] - p0[0]), abs(p3[0] - p0[0]),
              abs(p1[1] - p0[1]), abs(p2[1] - p0[1]), abs(p3[1] - p0[1]))
    n = max(2, int(math.ceil(ext / step)))
    pts = []
    for k in range(1, n + 1):
        t = k / n
        mt = 1.0 - t
        x = mt * mt * mt * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t * t * t * p3[0]
        y = mt * mt * mt * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t * t * t * p3[1]
        pts.append((x, y))
    return pts


def _quad_points(p0, p1, p2, step):
    ext = max(abs(p1[0] - p0[0]), abs(p2[0] - p0[0]), abs(p1[1] - p0[1]), abs(p2[1] - p0[1]))
    n = max(2, int(math.ceil(ext / step)))
    pts = []
    for k in range(1, n + 1):
        t = k / n
        mt = 1.0 - t
        x = mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0]
        y = mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def _arc_points(x0, y0, rx, ry, phi_deg, large, sweep, x1, y1, step):
    """SVG 椭圆弧 → 折线点列（标准中心参数化）。"""
    rx, ry = abs(rx), abs(ry)
    if rx < 1e-9 or ry < 1e-9:
        return [(x1, y1)]
    phi = math.radians(phi_deg % 360.0)
    cosp, sinp = math.cos(phi), math.sin(phi)
    dx, dy = (x0 - x1) / 2.0, (y0 - y1) / 2.0
    x1p = cosp * dx + sinp * dy
    y1p = -sinp * dx + cosp * dy
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1.0:
        s = math.sqrt(lam)
        rx *= s
        ry *= s
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    if den <= 0:
        return [(x1, y1)]
    coef = math.sqrt(max(0.0, num / den))
    if large == sweep:
        coef = -coef
    cxp = coef * (rx * y1p / ry)
    cyp = coef * (-ry * x1p / rx)
    cx = cosp * cxp - sinp * cyp + (x0 + x1) / 2.0
    cy = sinp * cxp + cosp * cyp + (y0 + y1) / 2.0
    theta1 = math.atan2((y1p - cyp) / ry, (x1p - cxp) / rx)
    theta2 = math.atan2((-y1p - cyp) / ry, (-x1p - cxp) / rx)
    dtheta = theta2 - theta1
    if not sweep and dtheta > 0:
        dtheta -= 2 * math.pi
    if sweep and dtheta < 0:
        dtheta += 2 * math.pi
    n = max(2, int(math.ceil(abs(dtheta) * max(rx, ry) / step)))
    pts = []
    for k in range(1, n + 1):
        t = theta1 + dtheta * k / n
        x = cx + rx * math.cos(t) * cosp - ry * math.sin(t) * sinp
        y = cy + rx * math.cos(t) * sinp + ry * math.sin(t) * cosp
        pts.append((x, y))
    return pts


def _flatten_subpaths(cmds, step):
    """命令列表 → 子路径点列 [[(x,y), ...], ...]（隐式闭合由填充阶段处理）。"""
    subpaths = []
    cur = [0.0, 0.0]
    start = [0.0, 0.0]
    sub = None
    last_cmd = None
    last_ctrl = None
    for cmd, args in cmds:
        c = cmd
        if c in "Zz":
            if sub is not None:
                sub.append((start[0], start[1]))
                subpaths.append(sub)
                sub = None
            cur = [start[0], start[1]]
            last_cmd = c
            last_ctrl = None
            continue
        if c in "Mm":
            if sub is not None:
                sub.append((start[0], start[1]))
                subpaths.append(sub)
                sub = None
            x, y = args[0], args[1]
            if c == "m":
                x += cur[0]
                y += cur[1]
            cur = [x, y]
            start = [x, y]
            sub = [(x, y)]
            last_cmd = c
            last_ctrl = None
            continue
        if sub is None:
            sub = [(cur[0], cur[1])]
        rel = c.islower()
        base = c.upper()
        if base == "L":
            for k in range(0, len(args), 2):
                x, y = args[k], args[k + 1]
                if rel:
                    x += cur[0]
                    y += cur[1]
                sub.append((x, y))
                cur = [x, y]
        elif base == "H":
            for k in range(0, len(args), 1):
                x = args[k]
                if rel:
                    x += cur[0]
                sub.append((x, cur[1]))
                cur = [x, cur[1]]
        elif base == "V":
            for k in range(0, len(args), 1):
                y = args[k]
                if rel:
                    y += cur[1]
                sub.append((cur[0], y))
                cur = [cur[0], y]
        elif base == "C":
            for k in range(0, len(args), 6):
                x1, y1, x2, y2, x, y = args[k:k + 6]
                if rel:
                    x1 += cur[0]; y1 += cur[1]; x2 += cur[0]; y2 += cur[1]; x += cur[0]; y += cur[1]
                sub.extend(_bezier_points(tuple(cur), (x1, y1), (x2, y2), (x, y), step))
                cur = [x, y]
                last_ctrl = (x2, y2)
        elif base == "S":
            for k in range(0, len(args), 4):
                x2, y2, x, y = args[k:k + 4]
                if rel:
                    x2 += cur[0]; y2 += cur[1]; x += cur[0]; y += cur[1]
                if last_cmd in ("C", "S") and last_ctrl is not None:
                    x1, y1 = 2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1]
                else:
                    x1, y1 = cur
                sub.extend(_bezier_points(tuple(cur), (x1, y1), (x2, y2), (x, y), step))
                cur = [x, y]
                last_ctrl = (x2, y2)
        elif base == "Q":
            for k in range(0, len(args), 4):
                x1, y1, x, y = args[k:k + 4]
                if rel:
                    x1 += cur[0]; y1 += cur[1]; x += cur[0]; y += cur[1]
                sub.extend(_quad_points(tuple(cur), (x1, y1), (x, y), step))
                cur = [x, y]
                last_ctrl = (x1, y1)
        elif base == "T":
            for k in range(0, len(args), 2):
                x, y = args[k], args[k + 1]
                if rel:
                    x += cur[0]
                    y += cur[1]
                if last_cmd in ("Q", "T") and last_ctrl is not None:
                    x1, y1 = 2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1]
                else:
                    x1, y1 = cur
                sub.extend(_quad_points(tuple(cur), (x1, y1), (x, y), step))
                cur = [x, y]
                last_ctrl = (x1, y1)
        elif base == "A":
            for k in range(0, len(args), 7):
                rx, ry, rot, large, sweep, x, y = args[k:k + 7]
                if rel:
                    x += cur[0]
                    y += cur[1]
                sub.extend(_arc_points(cur[0], cur[1], rx, ry, rot, large != 0, sweep != 0, x, y, step))
                cur = [x, y]
                last_ctrl = None
        last_cmd = c
    if sub is not None:
        subpaths.append(sub)
    return subpaths


def _mat_mul(m1, m2):
    """仿射矩阵相乘（结果 = 先应用 m2，再应用 m1）。"""
    a1, b1, c1, d1, e1, f1 = m1
    a2, b2, c2, d2, e2, f2 = m2
    return (a1 * a2 + c1 * b2, b1 * a2 + d1 * b2,
            a1 * c2 + c1 * d2, b1 * c2 + d1 * d2,
            a1 * e2 + c1 * f2 + e1, b1 * e2 + d1 * f2 + f1)


def _mat_apply(m, x, y):
    a, b, c, d, e, f = m
    return (a * x + c * y + e, b * x + d * y + f)


def _group_matrix(tx, ty, px, py, rot_deg, sx, sy):
    """VectorDrawable group 变换：T(translate+pivot) ∘ R(rot) ∘ S(scale) ∘ T(-pivot)。"""
    r = math.radians(rot_deg)
    cosr, sinr = math.cos(r), math.sin(r)
    R = (cosr, sinr, -sinr, cosr, 0.0, 0.0)
    S = (sx, 0.0, 0.0, sy, 0.0, 0.0)
    Tm = (1.0, 0.0, 0.0, 1.0, -px, -py)
    Tp = (1.0, 0.0, 0.0, 1.0, tx + px, ty + py)
    return _mat_mul(Tp, _mat_mul(R, _mat_mul(S, Tm)))


def _collect_edges(subpaths):
    """收集多边形边 [(x1, y1, x2, y2)]（跳过水平边）。"""
    edges = []
    for pts in subpaths:
        n = len(pts)
        if n < 3:
            continue
        for i in range(n):
            x1, y1 = pts[i]
            x2, y2 = pts[(i + 1) % n]
            if y1 != y2:
                edges.append((x1, y1, x2, y2))
    return edges


def _fill_mask_py(mask, subpaths, fill_rule="nonzero"):
    """纯 Python 扫描线填充 'L' 掩码（支持 nonzero / evenodd）。numpy 缺失时的回退。"""
    w, h = mask.size
    px = mask.load()
    edges = _collect_edges(subpaths)
    if not edges:
        return
    y_min = min(min(e[1], e[3]) for e in edges)
    y_max = max(max(e[1], e[3]) for e in edges)
    y_lo = max(0, int(math.floor(y_min)))
    y_hi = min(h, int(math.ceil(y_max)))
    for y in range(y_lo, y_hi):
        yy = y + 0.5
        xs = []
        for (x1, y1, x2, y2) in edges:
            if (y1 <= yy < y2) or (y2 <= yy < y1):
                t = (yy - y1) / (y2 - y1)
                xs.append((x1 + t * (x2 - x1), 1 if y2 > y1 else -1))
        if not xs:
            continue
        xs.sort(key=lambda p: p[0])
        acc = 0
        start_x = None
        for x, wnd in xs:
            if fill_rule == "evenodd":
                if acc == 0:
                    start_x = x
                acc ^= 1
            else:
                if acc == 0:
                    start_x = x
                acc += wnd
            if acc == 0 and start_x is not None:
                a = max(0, int(math.ceil(start_x - 0.5)))
                b = min(w, int(math.floor(x + 0.5)))
                for xx in range(a, b):
                    px[xx, y] = 255
                start_x = None


def _build_fill_mask(W, H, subpaths, fill_rule="nonzero"):
    """生成 L 模式填充掩码 Image，支持 nonzero / evenodd 填充规则。

    numpy 可用时向量化（快一个数量级以上），否则回退 _fill_mask_py。
    扫描线判定用半开规则（y1 <= yy < y2 或 y2 <= yy < y1），与纯 Python 版一致。
    """
    if np is None:
        mask = Image.new("L", (W, H), 0)
        _fill_mask_py(mask, subpaths, fill_rule)
        return mask

    arr = np.zeros((H, W), dtype=np.uint8)
    edges = _collect_edges(subpaths)
    if not edges:
        return Image.fromarray(arr, "L")

    x1 = np.array([e[0] for e in edges], dtype=np.float64)
    y1 = np.array([e[1] for e in edges], dtype=np.float64)
    x2 = np.array([e[2] for e in edges], dtype=np.float64)
    y2 = np.array([e[3] for e in edges], dtype=np.float64)
    y_lo = max(0, int(math.floor(min(y1.min(), y2.min()))))
    y_hi = min(H, int(math.ceil(max(y1.max(), y2.max()))))
    if y_lo >= y_hi:
        return Image.fromarray(arr, "L")

    ys = np.arange(y_lo, y_hi) + 0.5
    # 每条边在每个扫描线是否相交（半开规则）
    cross = ((y1 <= ys[:, None]) & (ys[:, None] < y2)) | ((y2 <= ys[:, None]) & (ys[:, None] < y1))
    t = (ys[:, None] - y1[None, :]) / (y2[None, :] - y1[None, :])
    xs = np.where(cross, x1[None, :] + t * (x2[None, :] - x1[None, :]), np.nan)
    wnd = np.where(y2 > y1, 1.0, -1.0)

    for r in range(len(ys)):
        row = xs[r]
        keep = ~np.isnan(row)
        if not keep.any():
            continue
        row = row[keep]
        y = y_lo + r
        if fill_rule == "evenodd":
            row.sort()
            starts = row[0::2]
            ends = row[1::2]
        else:
            wrow = wnd[keep]
            order = np.argsort(row, kind="stable")
            row = row[order]
            acc = np.cumsum(wrow[order])
            inside = acc != 0
            if not inside.any():
                continue
            # bool 数组直接 np.diff 得到的是异或（bool），必须转整型才能区分 +/-1
            trans = np.diff(np.concatenate(([0], inside.astype(np.int8), [0])))
            starts = row[np.flatnonzero(trans == 1)]
            ends = row[np.flatnonzero(trans == -1)]
        for a, b in zip(starts, ends):
            ia = max(0, int(math.ceil(a - 0.5)))
            ib = min(W, int(math.floor(b + 0.5)))
            if ia < ib:
                arr[y, ia:ib] = 255
    return Image.fromarray(arr, "L")


def _parse_gradient(xml_out):
    """解析 aapt2 拆分出来的 <gradient> drawable（$xxx__0.xml），失败返回 None。"""
    elems = _parse_vector_elements(xml_out)
    if not elems or elems[0]["tag"] != "gradient":
        return None
    attrs = elems[0]["attrs"]
    grad = {
        "type": int(_attr_float(attrs, "type", 0.0) or 0),  # 0=linear 1=radial 2=sweep
        "startX": _attr_float(attrs, "startX", 0.0),
        "startY": _attr_float(attrs, "startY", 0.0),
        "endX": _attr_float(attrs, "endX", 0.0),
        "endY": _attr_float(attrs, "endY", 0.0),
        "centerX": _attr_float(attrs, "centerX", 0.0),
        "centerY": _attr_float(attrs, "centerY", 0.0),
        "radius": _attr_float(attrs, "gradientRadius", 0.0),
        "angle": _attr_float(attrs, "angle", 0.0),
        "stops": [],
    }
    for el in elems[1:]:
        if el["tag"] != "item":
            continue
        a = el["attrs"]
        if "color" not in a:
            continue
        try:
            c = parse_android_color(a["color"])
        except ValueError:
            continue
        grad["stops"].append((_attr_float(a, "offset", 0.0), c))
    if not grad["stops"]:
        return None
    grad["stops"].sort(key=lambda s: s[0])
    if grad["stops"][0][0] > 0:
        grad["stops"].insert(0, (0.0, grad["stops"][0][1]))
    if grad["stops"][-1][0] < 1:
        grad["stops"].append((1.0, grad["stops"][-1][1]))
    return grad


def _sample_gradient_stops(stops, t):
    if t <= stops[0][0]:
        return stops[0][1]
    if t >= stops[-1][0]:
        return stops[-1][1]
    for i in range(1, len(stops)):
        o2, c2 = stops[i]
        if t <= o2:
            o1, c1 = stops[i - 1]
            span = o2 - o1
            k = 0.0 if span <= 0 else (t - o1) / span
            return (
                int(c1[0] + (c2[0] - c1[0]) * k),
                int(c1[1] + (c2[1] - c1[1]) * k),
                int(c1[2] + (c2[2] - c1[2]) * k),
                int(c1[3] + (c2[3] - c1[3]) * k),
            )
    return stops[-1][1]


def _sample_gradient_stops_vec(stops, t):
    """_sample_gradient_stops 的向量化版本：t 为 (H, W) 数组，返回 (H, W, 4) float。"""
    offsets = np.array([s[0] for s in stops], dtype=np.float64)
    colors = np.array([s[1] for s in stops], dtype=np.float64)  # (K, 4)
    if len(stops) < 2:
        return np.broadcast_to(colors[0], t.shape + (4,)).copy()
    t = np.clip(t, offsets[0], offsets[-1])
    idx = np.clip(np.searchsorted(offsets, t, side="right") - 1, 0, len(stops) - 2)
    span = offsets[idx + 1] - offsets[idx]
    k = np.divide(t - offsets[idx], span, out=np.zeros_like(t), where=span > 0)
    k = k[..., None]
    return colors[idx] + (colors[idx + 1] - colors[idx]) * k


def _render_gradient(W, H, grad, m):
    """按 viewport 坐标渲染 W×H 渐变图（m 把 viewport 坐标映射到像素坐标）。

    numpy 可用时整图向量化，否则回退逐像素的 _render_gradient_py。
    """
    if np is None:
        return _render_gradient_py(W, H, grad, m)
    stops = grad["stops"]
    gt = grad["type"]
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float64)
    if gt == 0:  # linear
        sx, sy = _mat_apply(m, grad["startX"], grad["startY"])
        ex, ey = _mat_apply(m, grad["endX"], grad["endY"])
        dx, dy = ex - sx, ey - sy
        dd = dx * dx + dy * dy
        if dd < 1e-9:  # 无起点终点，退回角度方向
            a = math.radians(grad["angle"])
            dx, dy = math.cos(a), -math.sin(a)
            dd = 1.0
        t = ((xx - sx) * dx + (yy - sy) * dy) / dd
    elif gt == 1:  # radial
        cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
        det = m[0] * m[3] - m[1] * m[2]
        r_px = grad["radius"] * math.sqrt(abs(det)) if det else grad["radius"]
        t = np.hypot(xx - cx, yy - cy) / r_px if r_px > 1e-9 else np.zeros_like(xx)
    else:  # sweep
        cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
        t = (np.arctan2(yy - cy, xx - cx) + math.pi) / (2.0 * math.pi)
    rgba = _sample_gradient_stops_vec(stops, t)
    return Image.fromarray(rgba.astype(np.uint8), "RGBA")


def _render_gradient_py(W, H, grad, m):
    """纯 Python 逐像素渲染渐变（numpy 缺失时的回退，语义与向量化版一致）。"""
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    px = img.load()
    stops = grad["stops"]
    gt = grad["type"]
    if gt == 0:  # linear
        sx, sy = _mat_apply(m, grad["startX"], grad["startY"])
        ex, ey = _mat_apply(m, grad["endX"], grad["endY"])
        dx, dy = ex - sx, ey - sy
        dd = dx * dx + dy * dy
        if dd < 1e-9:  # 无起点终点，退回角度方向
            a = math.radians(grad["angle"])
            dx, dy = math.cos(a), -math.sin(a)
            dd = 1.0
        for y in range(H):
            for x in range(W):
                t = ((x - sx) * dx + (y - sy) * dy) / dd
                px[x, y] = _sample_gradient_stops(stops, t)
    elif gt == 1:  # radial
        cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
        det = m[0] * m[3] - m[1] * m[2]
        r_px = grad["radius"] * math.sqrt(abs(det)) if det else grad["radius"]
        for y in range(H):
            for x in range(W):
                t = math.hypot(x - cx, y - cy) / r_px if r_px > 1e-9 else 0.0
                px[x, y] = _sample_gradient_stops(stops, t)
    else:  # sweep
        cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
        inv = 1.0 / (2.0 * math.pi)
        for y in range(H):
            for x in range(W):
                t = (math.atan2(y - cy, x - cx) + math.pi) * inv
                px[x, y] = _sample_gradient_stops(stops, t)
    return img


def _resolve_vector_fill(apk_path, full_res, color_value, index=None):
    """
    解析 vector 的 fillColor / strokeColor 属性值（可能带资源引用）。
    返回 ("color", (r,g,b,a))、("gradient", grad_dict) 或 None。
    """
    v = (color_value or "").strip()
    if v.startswith("#"):
        try:
            return ("color", parse_android_color(v))
        except ValueError:
            return None
    ref = v[1:] if v.startswith("@") else v
    ref = ref.lower()
    if not ref.startswith("0x"):
        return None
    if ref.startswith("0x01"):
        if ref in _FRAMEWORK_COLOR_MAP:
            return ("color", parse_android_color(_FRAMEWORK_COLOR_MAP[ref]))
        return None
    if not full_res:
        full_res = run_aapt2_dump_resource(apk_path)
    info = get_resource_info(extract_resource_entry(full_res, ref, index))
    if info["type"] == "color":
        try:
            return ("color", parse_android_color(info["value"]))
        except ValueError:
            return None
    if info["type"] in ("vector", "string_file", "image") and info["value"]:
        # 可能是 aapt2 拆分出来的渐变 drawable（$xxx__0.xml）
        grad = _parse_gradient(run_aapt2_dump_xmltree(apk_path, info["value"]))
        if grad:
            return ("gradient", grad)
    return None


def _draw_stroke(layer, subpaths, color, alpha, wpx, cap):
    stroke = Image.new("RGBA", layer.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(stroke)
    col = (color[0], color[1], color[2], int(round(color[3] * alpha)))
    r = wpx / 2.0
    for pts in subpaths:
        if len(pts) < 2:
            continue
        d.line([(round(p[0]), round(p[1])) for p in pts], fill=col, width=wpx, joint="curve")
        if cap == 1:  # round
            for p in (pts[0], pts[-1]):
                d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=col)
    layer.alpha_composite(stroke)


def rasterize_vector_layer(apk_path, xml_path, size, full_res=None, index=None):
    """
    把 Android VectorDrawable（aapt2 dump xmltree 输出）栅格化为 size×size RGBA 图像。
    支持 vector / group / path、填充与描边、nonzero/evenodd 填充规则、
    以及带资源引用的填充（含 aapt2 拆分出来的 <gradient> 渐变）。
    """
    xml_out = run_aapt2_dump_xmltree(apk_path, xml_path)
    if not xml_out.strip():
        return None
    elems = _parse_vector_elements(xml_out)
    root = None
    for el in elems:
        if el["tag"] == "vector":
            root = el
            break
    if root is None:
        return None
    attrs = root["attrs"]
    vw = _attr_float(attrs, "viewportWidth", _attr_float(attrs, "width", 108.0))
    vh = _attr_float(attrs, "viewportHeight", _attr_float(attrs, "height", 108.0))
    if vw <= 0 or vh <= 0:
        vw = vh = 108.0
    ss = 2  # 超采样，最后 LANCZOS 缩小抗锯齿
    W = size * ss
    H = size * ss
    sx = W / vw
    sy = H / vh
    step = max(0.5, max(vw, vh) / 160.0)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    transparent = Image.new("RGBA", (W, H), (0, 0, 0, 0))  # 每路径复用的透明底图
    vec_alpha = _attr_float(attrs, "alpha", 1.0)
    stack = []  # (indent, 累计矩阵, 累计 alpha)
    for el in elems:
        tag = el["tag"]
        indent = el["indent"]
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if tag == "vector":
            stack.append((indent, (1.0, 0.0, 0.0, 1.0, 0.0, 0.0), vec_alpha))
            continue
        if tag == "group":
            if not stack:
                continue
            a = el["attrs"]
            m = _group_matrix(
                _attr_float(a, "translateX", 0.0), _attr_float(a, "translateY", 0.0),
                _attr_float(a, "pivotX", 0.0), _attr_float(a, "pivotY", 0.0),
                _attr_float(a, "rotation", 0.0),
                _attr_float(a, "scaleX", 1.0), _attr_float(a, "scaleY", 1.0),
            )
            pm, pa = stack[-1][1], stack[-1][2]
            stack.append((indent, _mat_mul(pm, m), pa * _attr_float(a, "alpha", 1.0)))
            continue
        if tag == "path":
            if not stack:
                continue
            pm, pa = stack[-1][1], stack[-1][2]
            a = el["attrs"]
            path_data = a.get("pathData")
            if not path_data:
                continue
            cmds = _parse_path_commands(_tokenize_path_data(path_data))
            subpaths = _flatten_subpaths(cmds, step)
            if not subpaths:
                continue
            m = _mat_mul((sx, 0.0, 0.0, sy, 0.0, 0.0), pm)
            tsubs = [[_mat_apply(m, x, y) for (x, y) in pts] for pts in subpaths]
            fill_rule = "evenodd" if str(a.get("fillType", "")).lower() == "evenodd" else "nonzero"
            if "fillColor" in a:
                fill = _resolve_vector_fill(apk_path, full_res, a["fillColor"], index)
                if fill is not None:
                    falpha = pa * _attr_float(a, "fillAlpha", 1.0)
                    if fill[0] == "color":
                        ca = int(round(fill[1][3] * falpha))
                        if ca > 0:
                            mask = _build_fill_mask(W, H, tsubs, fill_rule)
                            tint = Image.new("RGBA", (W, H), (fill[1][0], fill[1][1], fill[1][2], ca))
                            layer.alpha_composite(Image.composite(tint, transparent, mask))
                    else:  # gradient 填充
                        mask = _build_fill_mask(W, H, tsubs, fill_rule)
                        gimg = _render_gradient(W, H, fill[1], m)
                        if falpha < 0.999:
                            gimg = gimg.point(lambda v: int(round(v * falpha)))
                        layer.alpha_composite(Image.composite(gimg, transparent, mask))
            if "strokeColor" in a:
                sc = _resolve_vector_fill(apk_path, full_res, a["strokeColor"], index)
                if sc is not None and sc[0] == "color":
                    stroke_color = sc[1]
                    sw = _attr_float(a, "strokeWidth", 0.0)
                    sa = pa * _attr_float(a, "strokeAlpha", 1.0)
                    if sw > 0 and sa > 0:
                        wpx = max(1, int(round(sw * min(sx, sy))))
                        cap = _VECTOR_CAPS.get(str(a.get("strokeLineCap", "butt")).lower(), 0)
                        _draw_stroke(layer, tsubs, stroke_color, sa, wpx, cap)
    return layer.resize((size, size), Image.LANCZOS)


def _trim_to_content(img, size):
    """
    裁掉图标四周的"空边"并放大铺满画布，消除纯色背景（如白色）导致的白边：
    - 四角透明 → 按 alpha 内容包围盒裁剪；
    - 四角为统一纯色 → 按与纯色差异的包围盒裁剪；
    - 四角颜色不同（设计铺满画布）→ 原样返回。
    内容已基本铺满（≥97%）时不裁剪。
    """
    w, h = img.size
    corners = [img.getpixel(p) for p in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1))]
    if all(c[3] < 16 for c in corners):
        bbox = img.split()[3].getbbox()
        pad_color = None  # 透明垫边
    else:
        base = corners[0]
        if not all(c[3] >= 240 and all(abs(c[i] - base[i]) <= 8 for i in range(3)) for c in corners):
            return img  # 角落颜色不一，设计铺满画布
        solid = Image.new("RGB", (w, h), base[:3])
        diff = ImageChops.difference(img.convert("RGB"), solid)
        r, g, b = diff.split()
        mask = ImageChops.lighter(
            ImageChops.lighter(r.point(lambda v: 255 if v > 12 else 0),
                               g.point(lambda v: 255 if v > 12 else 0)),
            b.point(lambda v: 255 if v > 12 else 0),
        )
        bbox = mask.getbbox()
        pad_color = base
    if not bbox:
        return img
    minx, miny, maxx, maxy = bbox
    if (maxx - minx) >= w * 0.97 and (maxy - miny) >= h * 0.97:
        return img
    pad = max(2, int(min(w, h) * 0.01))
    box = (max(0, minx - pad), max(0, miny - pad), min(w, maxx + pad), min(h, maxy + pad))
    crop = img.crop(box)
    cw, ch = crop.size
    if abs(cw - ch) <= max(cw, ch) * 0.15:
        return crop.resize((size, size), Image.LANCZOS)
    scale = min(size / cw, size / ch)
    nw, nh = max(1, int(cw * scale)), max(1, int(ch * scale))
    small = crop.resize((nw, nh), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), pad_color if pad_color is not None and pad_color[3] >= 240 else (0, 0, 0, 0))
    canvas.alpha_composite(small, ((size - nw) // 2, (size - nh) // 2))
    return canvas

def load_resource(apk_path, res_path_or_color, size, full_res=None, index=None):
    """
    根据输入判断是颜色、矢量还是图片：
    - 颜色：返回一个填充颜色的 Image
    - 矢量：栅格化 VectorDrawable XML
    - 图片：从 APK 中读取并缩放
    """
    typ = res_path_or_color["type"]
    if typ == "color":  # 颜色
        color = parse_android_color(res_path_or_color["value"])
        return Image.new("RGBA", (size, size), color)
    if typ == "vector":  # 矢量 drawable
        img = rasterize_vector_layer(apk_path, res_path_or_color["value"], size, full_res, index)
        if img is not None:
            return img
        raise ValueError(f"矢量图标栅格化失败: {res_path_or_color['value']}")
    # 位图文件
    with zipfile.ZipFile(apk_path, "r") as apk:
        with apk.open(res_path_or_color["value"]) as f:
            img = Image.open(f).convert("RGBA")
    return img.resize((size, size), Image.LANCZOS)

def _place_by_gravity(size: int, w: int, h: int, gravity: int):
    """按 Android gravity 位把 w×h 的图放到 size×size 画布上的 (x, y)。

    gravity 是位掩码：横向 0x07（LEFT=0x03 / CENTER_HORIZONTAL=0x01 /
    RIGHT=0x05），纵向 0x70（TOP=0x30 / CENTER_VERTICAL=0x10 / BOTTOM=0x50）。
    必须按掩码比较：直接 `gravity & 0x01` 会把 LEFT(0x03) 误判为居中，
    `gravity & 0x05` 会把 LEFT/TOP 误判为 RIGHT/BOTTOM（0x03&0x05=1）。
    """
    hg = gravity & 0x07
    vg = gravity & 0x70
    if hg == 0x01:      # CENTER_HORIZONTAL
        x = (size - w) // 2
    elif hg == 0x05:    # RIGHT
        x = size - w
    else:               # LEFT
        x = 0
    if vg == 0x10:      # CENTER_VERTICAL
        y = (size - h) // 2
    elif vg == 0x50:    # BOTTOM
        y = size - h
    else:               # TOP
        y = 0
    return x, y


def extract_icon_bytes(apk_path, foreground, background, size=512, fg_scale=None, full_res=None, index=None):
    """
    自动解析 adaptive icon 的前景和背景，合成完整 PNG，返回字节流。

    fg_scale: (width%, height%, gravity)，来自 <scale> 包装 drawable；
              None 表示前景按整层尺寸渲染。
    """
    # 加载前景
    foreground_img = load_resource(apk_path, foreground, size, full_res, index)
    # 加载背景
    background_img = load_resource(apk_path, background, size, full_res, index)

    if fg_scale:
        w_pct, h_pct, gravity = fg_scale
        w = max(1, int(size * w_pct / 100.0))
        h = max(1, int(size * h_pct / 100.0))
        if (w, h) != (size, size):
            canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            small = foreground_img.resize((w, h), Image.LANCZOS)
            canvas.alpha_composite(small, _place_by_gravity(size, w, h, gravity))
            foreground_img = canvas

    # 合成 (背景在下，前景在上)
    final_img = Image.alpha_composite(background_img, foreground_img)

    # 裁掉纯色/透明空边，避免生成的图标带白边
    # final_img = _trim_to_content(final_img, size)

    # 转字节流
    output = io.BytesIO()
    final_img.save(output, format="PNG")
    return output.getvalue()

def parse_aapt2_output(text: str) -> dict:
    """
    解析 aapt2 dump badging 输出，返回结构化信息。
    优先中文应用名：zh-CN -> zh-HK -> zh-TW -> 通用 application-label -> application: label
    """
    info = {
        "package_name": "",
        "version_name": "",
        "version_code": "",
        "platform_build_version_name": "",
        "platform_build_version_code": "",
        "compile_sdk_version": "",
        "compile_sdk_codename": "",
        "min_sdk": "",
        "target_sdk": "",
        "app_name": "",
        "app_name_labels": {},  # locale -> label
        "launchable_activity": "",
        "permissions": [],
        "features": [],
        "implied_features": [],
        "supports_screens": [],
        "supports_any_density": "",
        "densities": [],
        "locales": [],
        "icons": {},  # density -> path
        "raw": text.strip(),
        "architectures": [],   # 新增：支持架构
    }

    # --- 基本信息 ---
    m_pkg = re.search(
        r"package:\s+name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']+)'.*?",
        text,
        re.S,
    )
    if m_pkg:
        info["package_name"] = m_pkg.group(1)
        info["version_code"] = m_pkg.group(2)
        info["version_name"] = m_pkg.group(3)

    # 平台/编译 SDK
    m_plat = re.search(
        r"platformBuildVersionName='([^']+)'", text
    )
    if m_plat:
        info["platform_build_version_name"] = m_plat.group(1)

    m_platc = re.search(
        r"platformBuildVersionCode='([^']+)'", text
    )
    if m_platc:
        info["platform_build_version_code"] = m_platc.group(1)

    m_compile = re.search(r"compileSdkVersion='([^']+)'", text)
    if m_compile:
        info["compile_sdk_version"] = m_compile.group(1)

    m_compile_code = re.search(r"compileSdkVersionCodename='([^']+)'", text)
    if m_compile_code:
        info["compile_sdk_codename"] = m_compile_code.group(1)

    # Sdk 版本
    m_min = re.search(r"minSdkVersion:'([^']+)'", text)
    if m_min:
        info["min_sdk"] = m_min.group(1)
    m_target = re.search(r"targetSdkVersion:'([^']+)'", text)
    if m_target:
        info["target_sdk"] = m_target.group(1)

    # --- 应用名（多语言） ---
    for loc, label in re.findall(r"application-label-([\w-]+):'([^']*)'", text):
        info["app_name_labels"][loc] = label

    # 通用标签
    m_label_generic = re.search(r"application-label:'([^']*)'", text)
    generic_label = m_label_generic.group(1) if m_label_generic else ""

    # application 节点的 label
    m_label_app = re.search(r"application:\s+label='([^']*)'", text)
    app_node_label = m_label_app.group(1) if m_label_app else ""

    # 选择优先中文
    for pref in ("zh-CN", "zh-HK", "zh-TW"):
        if info["app_name_labels"].get(pref):
            info["app_name"] = info["app_name_labels"][pref]
            break
    if not info["app_name"]:
        info["app_name"] = (
            generic_label
            or info["app_name_labels"].get("zh", "")
            or app_node_label
        )

    # --- 可启动 Activity ---
    m_launch = re.search(
        r"launchable-activity:\s+name='([^']*)'(?:\s+label='([^']*)')?", text
    )
    if m_launch:
        info["launchable_activity"] = m_launch.group(1)

    # --- 权限 ---
    info["permissions"] = [p for p in re.findall(r"uses-permission:\s+name='([^']+)'", text)]

    # --- Feature ---
    info["features"] = [f for f in re.findall(r"uses-feature:\s+name='([^']+)'", text)]
    info["implied_features"] = [
        f for f in re.findall(r"uses-implied-feature:\s+name='([^']+)'", text)
    ]

    # --- 支持屏幕/密度/语言 ---
    m_screens = re.search(r"supports-screens:\s+((?:'[^']+'\s*)+)", text)
    if m_screens:
        info["supports_screens"] = re.findall(r"'([^']+)'", m_screens.group(1))

    m_anyden = re.search(r"supports-any-density:\s+'([^']+)'", text)
    if m_anyden:
        info["supports_any_density"] = m_anyden.group(1)

    m_dens = re.search(r"densities:\s+((?:'[^']+'\s*)+)", text)
    if m_dens:
        info["densities"] = re.findall(r"'([^']+)'", m_dens.group(1))

    m_loc = re.search(r"locales:\s+((?:'[^']+'\s*)+)", text)
    if m_loc:
        info["locales"] = re.findall(r"'([^']+)'", m_loc.group(1))

    # --- 图标（按密度） ---
    for dens, path_ in re.findall(r"application-icon-([0-9]+):'([^']+)'", text):
        info["icons"][dens] = path_

    # --- 支持架构 ---
    archs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("native-code:") or line.startswith("alt-native-code:"):
            found = re.findall(r"'([^']+)'", line)
            archs.extend(found)
    info["architectures"] = archs

    return info

class _Cancelled(Exception):
    """内部取消信号：线程被 requestInterruption 时抛出让 run() 静默退出。"""


class IconWorker(QtCore.QThread):
    # 注意：不要命名为 finished——会遮蔽 QThread 内建 finished 信号，
    # 破坏 thread.finished.connect(deleteLater) 等惯用法。
    iconReady = QtCore.pyqtSignal(QtGui.QPixmap, bytes)  # 成功时发射（字节流供导出）
    failed = QtCore.pyqtSignal(str)  # 提取失败时发出，供 UI 可见提示

    def __init__(self, apk_path, icon_path, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path
        self.icon_path = icon_path

    def _check_cancel(self):
        if self.isInterruptionRequested():
            raise _Cancelled

    @staticmethod
    def _load_pixmap(pix: QtGui.QPixmap, data: bytes) -> bool:
        """把字节载入 QPixmap；Qt 解不了时用 PIL 转成标准 PNG 再试一次。"""
        if pix.loadFromData(data):
            return True
        try:
            img = Image.open(io.BytesIO(data)).convert("RGBA")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return bool(pix.loadFromData(buf.getvalue()))
        except Exception:
            return False

    def _extract_adaptive_icon(self) -> bytes:
        """
        自适应图标（.xml）提取：
        1) 从 xmltree 解析 foreground/background 资源地址，完整解析每一层
           （支持混淆字符串引用、无扩展名文件、<scale> 包装），
           两层都可栅格化时合成完整图标；
        2) 任一层是纯矢量、或结构不是标准 adaptive-icon 时，回退到
           icon xml 所属 mipmap 条目的最高密度位图（8.0 之前的传统图标）。

        `dump resources` 只在确实需要时执行（旧实现在拿到 fg/bg 地址前
        就 dump，非自适应图标也白白跑一次全量输出）。
        """
        self._check_cancel()
        xml_out = run_aapt2_dump_xmltree(self.apk_path, self.icon_path)

        fg_addr = find_adaptive_layer_addr(xml_out, "foreground")
        bg_addr = find_adaptive_layer_addr(xml_out, "background")

        full_res = None
        index = None
        if fg_addr and bg_addr:
            full_res = run_aapt2_dump_resource(self.apk_path)
            self._check_cancel()
            # 一次性索引全量输出，后续所有资源条目查询 O(1)
            index = _ResourceIndex(full_res)
            fg_kind, fg_val, fg_scale = resolve_icon_layer(self.apk_path, full_res, fg_addr, index=index)
            bg_kind, bg_val, _bg_scale = resolve_icon_layer(self.apk_path, full_res, bg_addr, index=index)
            self._check_cancel()
            if fg_kind in ("image", "color", "vector") and bg_kind in ("image", "color", "vector"):
                return extract_icon_bytes(
                    self.apk_path,
                    {"type": fg_kind, "value": fg_val},
                    {"type": bg_kind, "value": bg_val},
                    fg_scale=fg_scale,
                    full_res=full_res,
                    index=index,
                )

        # 回退：找 icon xml 所属 mipmap 条目的最高密度位图
        self._check_cancel()
        if full_res is None:
            full_res = run_aapt2_dump_resource(self.apk_path)
            self._check_cancel()
            index = _ResourceIndex(full_res)
        fallback = find_mipmap_fallback(full_res, self.icon_path, index)
        if fallback:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                img = Image.open(zf.open(fallback)).convert("RGBA")
            img = img.resize((512, 512), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        return b""

    def run(self):
        pix = QtGui.QPixmap()
        data = b""
        try:
            self._check_cancel()
            if self.icon_path.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
                with zipfile.ZipFile(self.apk_path, "r") as zf:
                    data = zf.open(self.icon_path).read()
                if not self._load_pixmap(pix, data):
                    raise ValueError(f"图标文件无法解码为图片: {self.icon_path}")

            elif self.icon_path.lower().endswith('.xml'):
                data = self._extract_adaptive_icon()
                if not data:
                    raise ValueError("自适应图标前景/背景为纯矢量，且未找到位图回退图标")
                if not self._load_pixmap(pix, data):
                    raise ValueError("合成后的图标无法解码为图片")
            else:
                raise ValueError(f"不支持的图标类型: {self.icon_path}")

        except _Cancelled:
            return  # 用户取消/窗口关闭：静默退出，不覆盖 UI 状态
        except Exception as e:
            logging.exception("子线程提取图标失败: %s", e)
            self.failed.emit(str(e))
            return  # 失败后不再 emit iconReady，避免清掉 failed 设置的提示

        self.iconReady.emit(pix, data)

class ApkInfoWorker(QtCore.QThread):
    """后台线程：运行 aapt2 dump badging，避免阻塞 UI"""
    resultReady = QtCore.pyqtSignal(str)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, apk_path, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path

    def run(self):
        try:
            output = run_aapt2_dump_badging(self.apk_path)
        except FileNotFoundError as e:
            self.failed.emit(str(e))
            return
        except Exception as e:
            self.failed.emit(f"执行 aapt2 失败：\n{e}")
            return
        self.resultReady.emit(output)


class DropLineEdit(QtWidgets.QLineEdit):
    fileDropped = QtCore.pyqtSignal(str)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptDrops(True)
        self.setPlaceholderText("将 APK 文件拖到这里，或点击右侧按钮选择…")

    def dragEnterEvent(self, e: QtGui.QDragEnterEvent):
        if e.mimeData().hasUrls():
            for url in e.mimeData().urls():
                if url.toLocalFile().lower().endswith(".apk"):
                    e.acceptProposedAction()
                    return
        e.ignore()

    def dropEvent(self, e: QtGui.QDropEvent):
        if not e.mimeData().hasUrls():
            e.ignore()
            return
        for url in e.mimeData().urls():
            local = url.toLocalFile()
            if local.lower().endswith(".apk"):
                e.acceptProposedAction()
                self.setText(local)
                self.fileDropped.emit(local)
                break


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("APK 信息查看器（aapt2）")
        self.setWindowIcon(QtGui.QIcon(local_resource_path("resources/logo.ico")))
        self.resize(1050, 700)
        self._busy = False
        # 线程对象必须长期持有引用：若线程仍在运行时 Python 引用被替换/回收，
        # PyQt 会在 QThread 析构时报 "QThread: Destroyed while thread is still running"。
        self._apk_workers = []
        self._icon_workers = []
        self._icon_gen = 0  # 图标提取代数，用于丢弃过期结果
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # 顶部：文件选择/拖放
        file_row = QtWidgets.QHBoxLayout()
        self.apk_path_edit = DropLineEdit()
        self.apk_path_edit.fileDropped.connect(self.process_apk)
        self.btn_browse = QtWidgets.QPushButton("打开 APK")
        self.btn_browse.clicked.connect(self.browse_apk)
        file_row.addWidget(self.apk_path_edit, stretch=1)
        file_row.addWidget(self.btn_browse)
        layout.addLayout(file_row)

        # 在顶部表单之前加图标显示
        self.icon_label = QtWidgets.QLabel()
        self.icon_label.setFixedSize(96, 96)
        self.icon_label.setScaledContents(True)

        # 新增导出按钮
        self.btn_export_icon = QtWidgets.QPushButton("导出图标")
        self.btn_export_icon.setVisible(False)  # 默认隐藏
        self.btn_export_icon.clicked.connect(self.export_icon)

        # 设置图标和按钮的水平布局
        icon_row = QtWidgets.QHBoxLayout()
        icon_row.addWidget(QLabel("APP图标："))
        icon_row.addSpacing(15)
        icon_row.addWidget(self.icon_label)
        icon_row.addSpacing(50)
        icon_row.addWidget(self.btn_export_icon)

        # 右侧可伸缩空白（保证整体布局自适应）
        icon_row.addStretch(1)

        # 添加到主布局
        layout.addLayout(icon_row)

        # 用于保存当前图标数据
        self._current_icon_bytes = None

        # 基本信息（表单）
        form = QtWidgets.QFormLayout()
        self.le_app_name = QtWidgets.QLineEdit(); self.le_app_name.setReadOnly(True)
        self.le_pkg = QtWidgets.QLineEdit(); self.le_pkg.setReadOnly(True)
        self.le_ver = QtWidgets.QLineEdit(); self.le_ver.setReadOnly(True)
        self.le_sdk = QtWidgets.QLineEdit(); self.le_sdk.setReadOnly(True)
        self.le_launch = QtWidgets.QLineEdit(); self.le_launch.setReadOnly(True)
        self.le_arch = QtWidgets.QLineEdit(); self.le_arch.setReadOnly(True)  # 新增架构显示

        form.addRow("APP 名称（优先中文）：", self.le_app_name)
        form.addRow("APK 包名：", self.le_pkg)
        form.addRow("版本号（name / code）：", self.le_ver)
        form.addRow("SDK（min / target / compile）：", self.le_sdk)
        form.addRow("启动 Activity：", self.le_launch)
        form.addRow("支持架构：", self.le_arch)   # 加入表单
        layout.addLayout(form)

        # 多行信息分组：权限、特性、语言/密度、其它
        grid = QtWidgets.QGridLayout()

        self.te_permissions = self._mk_grouped_text("权限（uses-permission）")
        self.te_features = self._mk_grouped_text("功能特性（uses-feature / implied）")
        self.te_locales = self._mk_grouped_text("本地化 / 屏幕 / 密度")
        self.te_other = self._mk_grouped_text("其它关键信息")

        grid.addWidget(self.te_permissions["group"], 0, 0)
        grid.addWidget(self.te_features["group"], 0, 1)
        grid.addWidget(self.te_locales["group"], 1, 0)
        grid.addWidget(self.te_other["group"], 1, 1)
        layout.addLayout(grid)

        # 在底部按钮上方加重命名功能
        rename_group = QtWidgets.QGroupBox("APK 重命名")
        rename_layout = QtWidgets.QHBoxLayout(rename_group)
        self.rename_preview = QtWidgets.QLineEdit()
        self.rename_preview.setReadOnly(True)
        btn_rename = QtWidgets.QPushButton("执行重命名")
        btn_rename.clicked.connect(self.do_rename)
        rename_layout.addWidget(self.rename_preview, stretch=1)
        rename_layout.addWidget(btn_rename)
        layout.addWidget(rename_group)

        # 原始输出
        raw_group = QtWidgets.QGroupBox("aapt2 原始输出")
        vg = QtWidgets.QVBoxLayout(raw_group)
        self.te_raw = QtWidgets.QPlainTextEdit()
        self.te_raw.setReadOnly(True)
        self.te_raw.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        vg.addWidget(self.te_raw)
        layout.addWidget(raw_group, stretch=1)

        # 底部按钮
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_about = QtWidgets.QPushButton(" 关于 ")
        self.btn_about.setIcon(QtGui.QIcon(local_resource_path("resources/info.png")))
        self.btn_about.clicked.connect(self.show_about)
        btn_row.addWidget(self.btn_about)
        self.btn_refresh = QtWidgets.QPushButton("重新解析")
        self.btn_refresh.clicked.connect(self.reparse_current)
        btn_copy = QtWidgets.QPushButton("复制摘要")
        btn_copy.clicked.connect(self.copy_summary)
        btn_row.addStretch(1)
        btn_row.addWidget(self.btn_refresh)
        btn_row.addWidget(btn_copy)
        layout.addLayout(btn_row)

    def _mk_grouped_text(self, title: str):
        group = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(group)
        te = QtWidgets.QPlainTextEdit()
        te.setReadOnly(True)
        te.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        layout.addWidget(te)
        return {"group": group, "edit": te}

    def browse_apk(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "选择 APK 文件", "", "APK 文件 (*.apk)"
        )
        if path:
            self.apk_path_edit.setText(path)
            self.process_apk(path)

    def process_apk(self, path: str):
        if not path or not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(self, "提示", "请选择有效的 APK 文件。")
            return
        if self._busy:
            QtWidgets.QMessageBox.information(self, "提示", "正在解析 APK，请稍候再试。")
            return
        self.set_busy(True)
        self._prune_workers()
        worker = ApkInfoWorker(path)
        self._apk_workers.append(worker)
        worker.resultReady.connect(self.on_apk_info_ready)
        worker.failed.connect(self.on_apk_info_failed)
        worker.start()

    def set_busy(self, busy: bool):
        self._busy = busy
        self.btn_refresh.setEnabled(not busy)
        self.btn_export_icon.setEnabled(not busy)
        self.btn_browse.setEnabled(not busy)
        self.apk_path_edit.setEnabled(not busy)
        if busy:
            self.setCursor(QtCore.Qt.WaitCursor)
            self.te_raw.setPlainText("正在解析 APK，请稍候…")
        else:
            self.unsetCursor()

    def _prune_workers(self):
        """清理已结束的线程对象；运行中的保留引用，防止 QThread 被 GC 时崩溃。"""
        for lst in (self._apk_workers, self._icon_workers):
            for t in [t for t in lst if not t.isRunning()]:
                t.deleteLater()
                lst.remove(t)

    def _start_icon_worker(self, apk_path: str, icon_path: str):
        """启动图标提取线程；先取消并等待仍在运行的旧线程，避免结果乱序。"""
        for t in self._icon_workers:
            if t.isRunning():
                t.requestInterruption()
        for t in [t for t in self._icon_workers if t.isRunning()]:
            t.wait(5000)
        self._prune_workers()

        self._icon_gen += 1
        gen = self._icon_gen
        worker = IconWorker(apk_path, icon_path)
        self._icon_workers.append(worker)
        worker.iconReady.connect(lambda pix, data, g=gen: self.on_icon_loaded(pix, data, g))
        worker.failed.connect(lambda msg, g=gen: self.on_icon_failed(msg, g))
        worker.start()

    def closeEvent(self, event):
        """关闭窗口前停止并等待所有后台线程，避免 QThread 运行中被销毁。"""
        threads = self._apk_workers + self._icon_workers
        for t in threads:
            if t.isRunning():
                t.requestInterruption()
        for t in threads:
            if not t.wait(8000):
                # aapt2 子进程阻塞时的兜底：应用即将退出，强制结束线程
                t.terminate()
                t.wait(2000)
        event.accept()

    def on_apk_info_ready(self, output: str):
        self.te_raw.setPlainText(output)
        info = parse_aapt2_output(output)
        self.fill_info(info)
        self.set_busy(False)

    def on_apk_info_failed(self, message: str):
        QtWidgets.QMessageBox.critical(self, "错误", message)
        self.set_busy(False)

    def reparse_current(self):
        text = self.te_raw.toPlainText()
        if not text.strip():
            return
        info = parse_aapt2_output(text)
        self.fill_info(info)

    def fill_info(self, info: dict):
        # 顶部字段
        self.le_app_name.setText(info.get("app_name", ""))
        self.le_pkg.setText(info.get("package_name", ""))
        version = f"{info.get('version_name','')} / {info.get('version_code','')}".strip(" /")
        self.le_ver.setText(version)

        sdk_map = load_sdk_versions()
        sdk_map = sdk_map if sdk_map is not None else {}
        def fmt_sdk(api_level: str) -> str:
            if not api_level or api_level == "?":
                return "?"
            return f"{api_level}({sdk_map[api_level]})" if api_level in sdk_map else api_level

        sdk = "min:{m}  target:{t}  compile:{c}".format(
            m=fmt_sdk(info.get("min_sdk", "?") or "?"),
            t=fmt_sdk(info.get("target_sdk", "?") or "?"),
            c=fmt_sdk(info.get("compile_sdk_version", "?") or "?"),
        )
        self.le_sdk.setText(sdk)
        self.le_launch.setText(info.get("launchable_activity", ""))

        archs = info.get("architectures", [])
        self.le_arch.setText(", ".join(archs) if archs else "(未检测到)")

        # 权限
        perms = info.get("permissions", [])
        self.te_permissions["edit"].setPlainText("\n".join(perms) if perms else "(无)")

        # 特性
        feats = info.get("features", [])
        implied = info.get("implied_features", [])
        feat_text = []
        if feats:
            feat_text.append("[uses-feature]")
            feat_text.extend(feats)
        if implied:
            if feat_text:
                feat_text.append("")
            feat_text.append("[uses-implied-feature]")
            feat_text.extend(implied)
        self.te_features["edit"].setPlainText("\n".join(feat_text) if feat_text else "(无)")

        # 语言/屏幕/密度
        loc = info.get("locales", [])
        screens = info.get("supports_screens", [])
        dens = info.get("densities", [])
        anyden = info.get("supports_any_density", "")
        loc_text = []
        loc_text.append(f"locales（{len(loc)}）: " + (", ".join(loc) if loc else "(无)"))
        loc_text.append(f"screens: " + (", ".join(screens) if screens else "(无)"))
        loc_text.append(f"densities: " + (", ".join(dens) if dens else "(无)"))
        if anyden:
            loc_text.append(f"supports-any-density: {anyden}")
        self.te_locales["edit"].setPlainText("\n".join(loc_text))

        # 其它关键信息
        other = []
        if info.get("platform_build_version_name"):
            other.append(f"platformBuildVersionName: {info['platform_build_version_name']}")
        if info.get("platform_build_version_code"):
            other.append(f"platformBuildVersionCode: {info['platform_build_version_code']}")
        if info.get("compile_sdk_codename"):
            other.append(f"compileSdkVersionCodename: {info['compile_sdk_codename']}")

        # 多语言应用名（展示几条）
        labels = info.get("app_name_labels", {})
        if labels:
            other.append("")
            other.append("[部分多语言应用名]")
            # 优先展示常见语言
            preferred = ["zh-CN", "zh-HK", "zh-TW", "en-GB", "en-US", "ja", "ko"]
            shown = set()
            for k in preferred:
                if k in labels and labels[k]:
                    other.append(f"{k}: {labels[k]}")
                    shown.add(k)
            # 再补充最多 5 条其它语言
            for k, v in labels.items():
                if len(shown) >= 5 + len(preferred):
                    break
                if k not in shown and v:
                    other.append(f"{k}: {v}")
                    shown.add(k)

        # 图标
        icons = info.get("icons", {})
        if icons:
            other.append("")
            other.append("[icons by density]")
            other.extend([f"{k}: {v}" for k, v in sorted(icons.items(), key=lambda x: int(x[0]))])

        self.te_other["edit"].setPlainText("\n".join(other) if other else "(无)")

        # 提取图标
        self.btn_export_icon.setVisible(False)
        apk_path = self.apk_path_edit.text().strip()
        if apk_path and os.path.isfile(apk_path):
            try:
                icons = info.get("icons", {})
                if icons:
                    # 选择最大 density 的 icon
                    best = max(icons.items(), key=lambda x: int(x[0]))
                    icon_path = best[1]

                    self.icon_label.clear()  # 先清空（含上次失败提示文本）
                    self._start_icon_worker(apk_path, icon_path)
            except Exception as e:
                logging.exception("提取图标失败: %s", e)

        # 生成重命名预览
        app_name = self.le_app_name.text().strip() or "App"
        # ver_text = self.le_ver.text().strip().replace(" / ", ".")
        ver_text = info.get('version_name','').strip() or "0.0"
        new_name = re.sub(r'[\\/:*?"<>|]', "_", f"{app_name}_{ver_text}.apk")
        self.rename_preview.setText(new_name)

    def copy_summary(self):
        lines = []
        lines.append(f"APP 名称: {self.le_app_name.text()}")
        lines.append(f"包名: {self.le_pkg.text()}")
        lines.append(f"版本: {self.le_ver.text()}")
        lines.append(f"SDK: {self.le_sdk.text()}")
        lines.append(f"启动 Activity: {self.le_launch.text()}")
        lines.append(f"支持架构: {self.le_arch.text()}")
        lines.append("")
        lines.append("[权限]")
        lines.append(self.te_permissions["edit"].toPlainText() or "(无)")
        lines.append("")
        lines.append("[特性]")
        lines.append(self.te_features["edit"].toPlainText() or "(无)")
        lines.append("")
        lines.append("[本地化/屏幕/密度]")
        lines.append(self.te_locales["edit"].toPlainText() or "(无)")

        summary = "\n".join(lines)
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(summary)
        QtWidgets.QMessageBox.information(self, "已复制", "已复制摘要到剪贴板。")

    def do_rename(self):
        old_path = self.apk_path_edit.text().strip()
        new_name = self.rename_preview.text().strip()
        if not old_path or not os.path.isfile(old_path):
            QtWidgets.QMessageBox.warning(self, "提示", "未选择有效的 APK 文件。")
            return
        if not new_name:
            QtWidgets.QMessageBox.warning(self, "提示", "没有生成新的文件名。")
            return
        new_path = str(Path(old_path).with_name(new_name))
        if os.path.abspath(new_path) == os.path.abspath(old_path):
            return
        if os.path.exists(new_path):
            ret = QtWidgets.QMessageBox.question(
                self, "覆盖确认",
                f"目标文件已存在：\n{new_path}\n\n是否覆盖？",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if ret != QtWidgets.QMessageBox.Yes:
                return
        try:
            # os.rename 在 Windows 上目标已存在时失败；os.replace 原子替换
            os.replace(old_path, new_path)
            QtWidgets.QMessageBox.information(self, "完成", f"已重命名为:\n{new_path}")
            self.apk_path_edit.setText(new_path)
            self.rename_preview.setText(new_name)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"重命名失败: {e}")

    def on_icon_loaded(self, pix: QtGui.QPixmap, data: bytes, gen: int):
        if gen != self._icon_gen:
            return  # 过期结果（用户已开始解析新 APK），丢弃
        self.icon_label.setPixmap(pix)
        if pix and not pix.isNull():
            self._current_icon_bytes = data
            self.btn_export_icon.setVisible(True)
        else:
            self._current_icon_bytes = None
            self.btn_export_icon.setVisible(False)

    def on_icon_failed(self, message: str, gen: int):
        if gen != self._icon_gen:
            return
        # 图标提取失败时给出可见提示（之前是静默空白）
        self.icon_label.setText("提取失败")
        self.icon_label.setToolTip(f"图标提取失败：{message}")
        self._current_icon_bytes = None
        self.btn_export_icon.setVisible(False)
        QtWidgets.QMessageBox.warning(self, "图标提取失败", f"无法提取该 APK 的图标。\n\n{message}")

    def export_icon(self):
        if not self._current_icon_bytes:
            QtWidgets.QMessageBox.warning(self, "提示", "当前没有可导出的图标。")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "保存图标", "app_icon.png", "PNG 图片 (*.png)"
        )
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(self._current_icon_bytes)
                QtWidgets.QMessageBox.information(self, "完成", f"图标已保存到:\n{path}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "错误", f"保存失败: {e}")

    def show_about(self):
        QtWidgets.QMessageBox.about(
            self,
            "About",
            "<b>APK 信息查看器</b><br><br>"
            "基于 PyQt5 + aapt2 的图形化<br>"
            "解析 APK 文件信息的工具程序<br><br>"
            '更多信息: <a href="https://github.com/Sinryou/WinApkInfo">项目主页</a><br>'
            "版本: 1.1.0<br>"
            "Copyright (c) 2025-2026 Sinryou.<br>At MIT License."
        )

def main():
    # 日志：控制台模式输出到 stderr；PyInstaller 窗口模式（无 stderr）落盘到临时目录
    if sys.stderr is not None:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            filename=os.path.join(tempfile.gettempdir(), "winapkinfo.log"),
        )

    # 高分屏适配：必须在 QApplication 创建之前设置。
    # Qt ≥ 5.14 起 high-DPI 缩放默认启用，再设置属性只会触发弃用警告；
    # Qt < 5.14 则在所有平台统一开启（旧代码只在非 Windows 设置）。
    qt_ver = tuple(int(x) for x in QtCore.QT_VERSION_STR.split(".")[:2])
    if (5, 6) <= qt_ver < (5, 14):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)

    app = QtWidgets.QApplication(sys.argv)
    # app.setStyleSheet("QLabel { font-size: 16px; font-family: Microsoft Yahei; }"
    # "QGroupBox { font-size: 16px; font-family: Microsoft Yahei; }")
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
