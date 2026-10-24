# -*- coding: utf-8 -*-
"""静态资源定位、SDK 版本表、资源索引与条目解析。"""
import os
import sys
import re
import json
import logging
import threading
import zipfile
import contextlib
from pathlib import Path


@contextlib.contextmanager
def open_apk_zip(apk_path: str, zf=None):
    """上下文管理器：若已提供有效 zf 句柄则复用，否则临时打开并在退出时关闭。"""
    if zf is not None:
        yield zf
    else:
        with zipfile.ZipFile(apk_path, "r") as local_zf:
            yield local_zf

# 密度从低到高，用于在多个密度变体中挑选最高分辨率
_DPI_ORDER = ["ldpi", "mdpi", "tvdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]


def local_resource_path(relative_path):
    """兼容打包前后路径。

    PyInstaller 打包模式下以 sys._MEIPASS 为根目录；
    未打包模式下以项目根目录为基准。
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base_path = getattr(sys, "_MEIPASS", project_root)
    return os.path.join(base_path, relative_path)


_sdk_versions_cache = None
_sdk_load_warned = False


def load_sdk_versions():
    """读取 resources/android_sdk_versions.json，**成功才缓存**。

    旧实现把"文件缺失/解析失败"得到的空表也写进缓存，之后永不重试，
    SDK 就只剩裸 API 级别可看（例如打包漏带 resources 时）。
    现在失败只返回空表并留下提示，下次调用会重新尝试。
    """
    global _sdk_versions_cache, _sdk_load_warned
    if _sdk_versions_cache:
        return _sdk_versions_cache

    sdk_map = {}
    sdk_file = Path(local_resource_path("resources/android_sdk_versions.json"))
    if not sdk_file.exists():
        if not _sdk_load_warned:
            logging.warning("未找到 %s，SDK 版本将只显示 API 级别", sdk_file)
            _sdk_load_warned = True
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
        if sdk_map:
            _sdk_versions_cache = sdk_map   # 仅在真正解析出内容时缓存
        else:
            logging.warning("%s 内容为空，SDK 版本将只显示 API 级别", sdk_file)
    except Exception as e:
        logging.warning("读取 android_sdk_versions.json 出错: %s", e)
    return sdk_map


def entry_span(lines, start):
    """返回资源条目 [start, end) 行区间：到下一个 `resource 0x` 或 `type ... id=` 分节行前。"""
    end = start + 1
    while end < len(lines):
        s = lines[end].strip()
        if s.startswith("resource 0x") or re.match(r"^type\s+\w+\s+id=", s):
            break
        end += 1
    return start, end


class _LazyEntryMap(dict):
    """基于字符区间切片的惰性资源映射，避免全量生成数十万个子字符串对象。"""
    __slots__ = ("_full_text",)

    def __init__(self, full_text: str):
        super().__init__()
        self._full_text = full_text or ""

    def __getitem__(self, key):
        val = super().__getitem__(key)
        if isinstance(val, tuple):
            return self._full_text[val[0]:val[1]]
        return val

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def values(self):
        for k in self:
            yield self[k]

    def items(self):
        for k in self:
            yield (k, self[k])


class ResourceIndex:
    """一次性解析 `aapt2 dump resources` 全量输出，提供 O(1) 的条目查询。

    采用惰性区间索引映射，避免对大型 APK（30MB+ 文本）全量调用 splitlines()
    和多次 \\n.join() 生成海量字符串碎片，将索引构建内存与耗时降低 70% 以上。
    by_id 按资源地址（小写 0x...）、by_name 按 `type/name` 形式的资源名、
    by_file 按条目内出现的文件路径索引。
    """

    __slots__ = ("by_id", "by_file", "by_name")

    def __init__(self, full_output: str):
        full_text = full_output or ""
        self.by_id = _LazyEntryMap(full_text)
        self.by_file = _LazyEntryMap(full_text)
        self.by_name = _LazyEntryMap(full_text)
        if not full_text:
            return

        pattern = re.compile(r"(?m)^\s*resource\s+(0x[0-9a-fA-F]+)(?:\s+(\S+))?")
        type_pattern = re.compile(r"(?m)^\s*type\s+\w+\s+id=")
        file_pattern = re.compile(r"(?m)^\s*\([^)]*\)\s*\(file\)\s*(\S+)")

        matches = list(pattern.finditer(full_text))
        n = len(matches)
        for idx, m in enumerate(matches):
            start = m.start()
            rid = m.group(1).lower()
            name = m.group(2)
            next_start = matches[idx + 1].start() if idx + 1 < n else len(full_text)
            tm = type_pattern.search(full_text, start, next_start)
            end = tm.start() if tm else next_start
            span = (start, end)
            dict.__setitem__(self.by_id, rid, span)
            if name:
                dict.__setitem__(self.by_name, name, span)
            # 直接在原文本上按偏移扫描文件行：为每个条目物化 entry_slice
            # 子串正是本类要避免的事（数十万条目会生成海量瞬时字符串）。
            pos = start
            while True:
                fm = file_pattern.search(full_text, pos, end)
                if fm is None:
                    break
                fpath = fm.group(1)
                if not dict.__contains__(self.by_file, fpath):
                    dict.__setitem__(self.by_file, fpath, span)
                pos = fm.end()


def _normalize_resource_key(res_id: str) -> str:
    """归一化资源引用键：剥掉 @ 前缀；数字地址统一小写。

    命名引用（color/brand）保留原始大小写：资源名大小写敏感，
    aapt2 dump 输出的别名值与条目头行里的名字来自同一张表，必然逐字符一致。
    """
    key = (res_id or "").strip()
    if key.startswith("@"):
        key = key[1:]
    if key[:2].lower() == "0x":
        key = key.lower()
    return key


def extract_resource_entry(full_output: str, res_id: str, index=None) -> str:
    """
    从 `aapt2 dump resources` 全量输出中精确截取某个资源条目。

    条目以 `resource 0x{id} <pkg>/<name>` 行开始，到下一个 `resource 0x` 行
    或 `type <type> id=..` 分节行之前结束（含其所有密度变体行）。

    res_id 支持两种形态（可带 @ 前缀）：
        - 数字地址：0x7f0600f1（大小写不敏感）；
        - 命名引用：color/feature_x（按条目头行的 type/name 查询）。
    找不到返回空字符串。传入 index（ResourceIndex）时 O(1) 查询。
    """
    key = _normalize_resource_key(res_id)
    is_hex = key[:2] == "0x"

    if index is not None:
        if is_hex:
            return index.by_id.get(key, "")
        return index.by_name.get(key, "")

    lines = (full_output or "").splitlines()
    start = None
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith("resource "):
            continue
        parts = s.split()
        if is_hex:
            if len(parts) >= 2 and parts[1] == key:
                start = i
                break
        elif len(parts) >= 3 and parts[2] == key:
            start = i
            break
    if start is None:
        return ""

    a, b = entry_span(lines, start)
    return "\n".join(lines[a:b])


def density_of(qualifier: str) -> str:
    """从配置限定符中提取密度（如 "xxhdpi"、"anydpi-v26"、"hdpi-v25"）。"""
    m = re.search(r"(ldpi|mdpi|tvdpi|hdpi|xhdpi|xxhdpi|xxxhdpi|nodpi|anydpi)", qualifier or "")
    return m.group(1) if m else ""


def pick_best_density(variants: dict):
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


def sniff_file_kind(apk_path: str, inner_path: str, zf=None):
    """
    用魔数识别 APK 内文件类型（AndResGuard 等混淆后文件没有扩展名）。
    返回 "image" / "xml" / None。结果按 (apk 路径, mtime, 文件路径) 缓存，
    避免同一次提取链路里反复打开同一个 zip（不长期持有 ZipFile 句柄，
    以免影响 Windows 上的重命名操作）。支持传入已有 zf 句柄以复用 I/O。
    """
    try:
        key = (os.path.abspath(apk_path), os.stat(apk_path).st_mtime_ns, inner_path)
    except OSError:
        return None
    with _sniff_cache_lock:
        if key in _sniff_cache:
            return _sniff_cache[key]
    try:
        with open_apk_zip(apk_path, zf) as local_zf:
            head = local_zf.open(inner_path).read(16)
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


# aapt2 dump resources 里「文件型」条目会标注 type=PNG / type=XML；
# 但 WebP 等位图不标注任何 type（形如 `(xxhdpi) (file) res/Sn.webp`），
# 所以位图识别必须按扩展名兜底，不能只看 type=PNG。
# 这是全项目唯一的位图扩展名清单：资源条目分类（本模块）、图标层
# 解析（apk_parser）与图标类型分派（ui.workers._icon_kind）共用。
BITMAP_EXTS = (".png", ".webp", ".jpg", ".jpeg", ".gif")

# 混淆包中字符串引用/包装 XML 的最大解引用深度，防止循环引用
MAX_DEREF_DEPTH = 3


def get_resource_info(entry_text: str) -> dict:
    """
    解析一个 aapt2 dump resources 资源条目（extract_resource_entry 的返回值）。

    返回：
        dict: {
            "type": "color",       "value": "#AARRGGBB"
            "type": "image",       "value": 最高密度位图路径（png/webp/jpg/gif）
            "type": "vector",      "value": xml 路径（矢量 drawable，无法直接栅格化）
            "type": "string_file", "value": 指向文件的字符串值（混淆包），需进一步解析
            "type": "ref",         "value": 另一个资源地址（数字 "0x0106003b" 或命名 "color/xxx"）
            "type": "unknown",     "value": None
        }

    "ref" 是 Android 资源别名，aapt2 有两种输出形态：
        - `() @0x0106003b`：数字形式（旧版 aapt2，RootMyVivo 的 launcher 颜色
          就全部是这种写法）；
        - `() @color/feature_x`：命名形式（aapt2 2.20+ 对表内引用直接输出
          解析后的名字，pixiv 6.201 的 adaptive 背景即此形态）。
    旧实现只认数字形式，命名别名会让颜色层被判为 unknown、整张图标透明。
    命名形式保留 `type/name` 原文（含 android: 包前缀的原样保留——框架资源
    不在应用资源表内，按名查询落空是预期行为）。
    """
    lines = (entry_text or "").splitlines()

    bitmaps = {}        # density -> path
    xml_files = []      # path
    string_files = []   # (density, value)
    color = None
    ref = None

    file_re = re.compile(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+?)(?:\s+type=(\w+))?\s*$")
    str_re = re.compile(r"^\s*\(([^)]*)\)\s*\"([^\"]+)\"\s*$")
    # #RGB / #ARGB / #RRGGBB / #AARRGGBB 都是合法颜色
    color_re = re.compile(r"^\s*\(\s*\)\s*(#[0-9a-fA-F]{3,8})\s*$")
    ref_re = re.compile(r"^\s*\(\s*\)\s*@?(0x[0-9a-fA-F]+)\s*$")
    named_ref_re = re.compile(r"^\s*\(\s*\)\s*@?((?:[\w.]+:)?[\w.]+/[\w.]+)\s*$")

    for line in lines[1:]:  # 跳过 `resource 0x..` 头部行
        m = file_re.match(line)
        if m:
            qual, path, typ = m.group(1).strip(), m.group(2), m.group(3)
            if typ == "PNG" or path.lower().endswith(BITMAP_EXTS):
                bitmaps[density_of(qual)] = path
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
                continue
        if ref is None:
            m = ref_re.match(line)
            if m:
                ref = m.group(1).lower()
                continue
            m = named_ref_re.match(line)
            if m:
                ref = m.group(1)

    if bitmaps:
        return {"type": "image", "value": pick_best_density(bitmaps)}
    if color:
        return {"type": "color", "value": color}
    if xml_files:
        return {"type": "vector", "value": xml_files[0]}
    if ref:
        return {"type": "ref", "value": ref}
    if string_files:
        return {"type": "string_file", "value": string_files[0][1]}
    return {"type": "unknown", "value": None}

