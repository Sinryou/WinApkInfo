# -*- coding: utf-8 -*-
import os
import sys
import re
import io
import shlex
import shutil
import subprocess
import json
from pathlib import Path
import zipfile
from PIL import Image

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QLabel


# subprocess.CREATE_NO_WINDOW 仅存在于 Windows；macOS/Linux 上访问会在运行时报
# AttributeError。此处按平台解析为固定常量，跨平台安全（非 Windows 传 0 即可）。
if sys.platform == "win32":
    _SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _SUBPROCESS_FLAGS = 0


def local_resource_path(relative_path):
    """兼容打包前后路径"""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.argv[0])))
    return os.path.join(base_path, relative_path)

_sdk_versions_cache = None

def load_sdk_versions():
    """尝试读取同级目录下 android_sdk_versions.json"""
    global _sdk_versions_cache
    if _sdk_versions_cache is not None:
        return _sdk_versions_cache
    sdk_map = {}
    # here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    # sdk_file = here / "android_sdk_versions.json"
    sdk_file = Path(local_resource_path("resources/android_sdk_versions.json"))
    if not sdk_file.exists():
        return
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
        return sdk_map
    except Exception as e:
        print("读取 android_sdk_versions.json 出错:", e)

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
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "badging", apk_path]

    # Windows 控制台编码兼容：优先 utf-8，失败再回退到 gbk
    try:
        out = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=_SUBPROCESS_FLAGS
        )
    except subprocess.CalledProcessError as e:
        # 即使非0，也尽量取输出
        out = e

    data = out.stdout or out.stderr
    text = None
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            text = data.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    if text is None:
        text = data.decode(errors="ignore")
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

    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=_SUBPROCESS_FLAGS)
        data = out.stdout or out.stderr
    except subprocess.CalledProcessError as e:
        data = e.stdout or e.stderr

    text = None
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            text = data.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    if text is None:
        text = data.decode(errors="ignore")
    return text


def extract_resource_entry(full_output: str, res_id: str) -> str:
    """
    从 `aapt2 dump resources` 全量输出中精确截取某个资源条目。

    条目以 `resource 0x{id} <pkg>/<name>` 行开始，到下一个 `resource 0x` 行
    或 `type <type> id=..` 分节行之前结束（含其所有密度变体行）。
    找不到返回空字符串。
    """
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

    end = start + 1
    while end < len(lines):
        s = lines[end].strip()
        if s.startswith("resource 0x") or re.match(r"^type\s+\w+\s+id=", s):
            break
        end += 1
    return "\n".join(lines[start:end])

def run_aapt2_dump_xmltree(apk_path: str, inner_file_path: str) -> str:
    """
    运行 `aapt2 dump xmltree "<apk>"` 并返回 stdout 文本。
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "xmltree", apk_path, "--file", inner_file_path]

    # Windows 控制台编码兼容：优先 utf-8，失败再回退到 gbk
    try:
        out = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=_SUBPROCESS_FLAGS
        )
    except subprocess.CalledProcessError as e:
        # 即使非0，也尽量取输出
        out = e

    data = out.stdout or out.stderr
    text = None
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            text = data.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    if text is None:
        text = data.decode(errors="ignore")
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


def _sniff_file_kind(apk_path: str, inner_path: str):
    """
    用魔数识别 APK 内文件类型（AndResGuard 等混淆后文件没有扩展名）。
    返回 "image" / "xml" / None。
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            head = zf.open(inner_path).read(16)
    except Exception:
        return None
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    if head[:4] == b"\x89PNG":
        return "image"
    if head[:2] == b"\xff\xd8":
        return "image"
    if head[:4] == b"GIF8":
        return "image"
    if head[:4] == b"\x03\x00\x08\x00":  # Android 二进制 XML 头
        return "xml"
    return None


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


def _resolve_xml_wrapper(apk_path: str, full_res: str, xml_path: str, depth: int):
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
        return (None, None, None)  # 纯矢量，无法继续解析
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
    kind, value, scale2 = resolve_icon_layer(apk_path, full_res, m.group(1), depth + 1)
    if not kind:
        return (None, None, None)
    return (kind, value, scale or scale2)


def resolve_icon_layer(apk_path: str, full_res: str, res_id: str, depth: int = 0):
    """
    把一个图标层资源完整解析成可渲染形态：
        ("color", "#AARRGGBB", None)
        ("image", "res/...png", None)
        ("vector", "res/...xml", None)   # 纯矢量，无法栅格化
        (None, None, None)               # 无法解析
    scale 参数 (width%, height%, gravity) 来自 <scale> 包装。

    支持混淆包的解引用链：字符串值指向文件、无扩展名文件按魔数识别、
    <scale> 包装继续跟随 android:drawable 引用；深度受限防止循环。
    """
    info = get_resource_info(extract_resource_entry(full_res, res_id))
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
            return _resolve_xml_wrapper(apk_path, full_res, value, depth)
        sniffed = _sniff_file_kind(apk_path, value)
        if sniffed == "image":
            return ("image", value, None)
        if sniffed == "xml":
            return _resolve_xml_wrapper(apk_path, full_res, value, depth)
        return (None, None, None)
    if kind == "vector" and value:
        kind2, value2, scale2 = _resolve_xml_wrapper(apk_path, full_res, value, depth)
        if kind2:
            return (kind2, value2, scale2)
        return ("vector", value, None)
    return (None, None, None)


def find_mipmap_fallback(full_res: str, icon_xml_path: str):
    """
    自适应图标（.xml）无法整体栅格化时的回退：
    找到包含该 icon xml 的资源条目（通常是 mipmap/ic_launcher），
    返回其最高密度的位图变体路径（即 8.0 之前使用的传统回退图标）。
    """
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
    end = target + 1
    while end < len(lines):
        s = lines[end].strip()
        if s.startswith("resource 0x") or re.match(r"^type\s+\w+\s+id=", s):
            break
        end += 1

    variants = {}
    for line in lines[start:end]:
        m = re.match(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+)", line)
        if m and m.group(2).lower().endswith(_BITMAP_EXTS):
            variants[_density_of(m.group(1))] = m.group(2)
    return _pick_best_density(variants)

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

def load_resource(apk, res_path_or_color, size):
    """
    根据输入判断是颜色还是图片：
    - 颜色：返回一个填充颜色的 Image
    - 图片：从 APK 中读取并缩放
    """
    if res_path_or_color["type"] == "color":  # 颜色
        color = parse_android_color(res_path_or_color["value"])
        return Image.new("RGBA", (size, size), color)
    else:  # 文件
        with apk.open(res_path_or_color["value"]) as f:
            img = Image.open(f).convert("RGBA")
        return img.resize((size, size), Image.LANCZOS)

def _place_by_gravity(size: int, w: int, h: int, gravity: int):
    """按 Android gravity 位把 w×h 的图放到 size×size 画布上的 (x, y)。"""
    if gravity & 0x01:      # CENTER_HORIZONTAL
        x = (size - w) // 2
    elif gravity & 0x05:    # RIGHT
        x = size - w
    else:                   # LEFT
        x = 0
    if gravity & 0x10:      # CENTER_VERTICAL
        y = (size - h) // 2
    elif gravity & 0x50:    # BOTTOM
        y = size - h
    else:                   # TOP
        y = 0
    return x, y


def extract_icon_bytes(apk_path, foreground, background, size=512, fg_scale=None):
    """
    自动解析 adaptive icon 的前景和背景，合成完整 PNG，返回字节流。

    fg_scale: (width%, height%, gravity)，来自 <scale> 包装 drawable；
              None 表示前景按整层尺寸渲染。
    """
    with zipfile.ZipFile(apk_path, 'r') as apk:
        # 加载前景
        foreground_img = load_resource(apk, foreground, size)
        # 加载背景
        background_img = load_resource(apk, background, size)

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

class IconWorker(QtCore.QThread):
    finished = QtCore.pyqtSignal(QtGui.QPixmap, bytes)  # 多发一个图标字节流
    failed = QtCore.pyqtSignal(str)  # 提取失败时发出，供 UI 可见提示

    def __init__(self, apk_path, icon_path, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path
        self.icon_path = icon_path

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
        """
        full_res = run_aapt2_dump_resource(self.apk_path)
        xml_out = run_aapt2_dump_xmltree(self.apk_path, self.icon_path)

        fg_addr = find_adaptive_layer_addr(xml_out, "foreground")
        bg_addr = find_adaptive_layer_addr(xml_out, "background")
        if fg_addr and bg_addr:
            fg_kind, fg_val, fg_scale = resolve_icon_layer(self.apk_path, full_res, fg_addr)
            bg_kind, bg_val, _bg_scale = resolve_icon_layer(self.apk_path, full_res, bg_addr)
            if fg_kind in ("image", "color") and bg_kind in ("image", "color"):
                return extract_icon_bytes(
                    self.apk_path,
                    {"type": fg_kind, "value": fg_val},
                    {"type": bg_kind, "value": bg_val},
                    fg_scale=fg_scale,
                )

        fallback = find_mipmap_fallback(full_res, self.icon_path)
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

        except Exception as e:
            print("子线程提取图标失败:", e)
            self.failed.emit(str(e))

        self.finished.emit(pix, data)

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
        for url in e.mimeData().urls():
            local = url.toLocalFile()
            if local.lower().endswith(".apk"):
                self.setText(local)
                self.fileDropped.emit(local)
                break


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("APK 信息查看器（aapt2）")
        self.setWindowIcon(QtGui.QIcon(local_resource_path("resources/logo.ico")))
        self.resize(1050, 700)
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # 顶部：文件选择/拖放
        file_row = QtWidgets.QHBoxLayout()
        self.apk_path_edit = DropLineEdit()
        self.apk_path_edit.fileDropped.connect(self.process_apk)
        btn_browse = QtWidgets.QPushButton("打开 APK")
        btn_browse.clicked.connect(self.browse_apk)
        file_row.addWidget(self.apk_path_edit, stretch=1)
        file_row.addWidget(btn_browse)
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
        self.set_busy(True)
        self._apk_worker = ApkInfoWorker(path)
        self._apk_worker.resultReady.connect(self.on_apk_info_ready)
        self._apk_worker.failed.connect(self.on_apk_info_failed)
        self._apk_worker.start()

    def set_busy(self, busy: bool):
        self.btn_refresh.setEnabled(not busy)
        self.btn_export_icon.setEnabled(not busy)
        if busy:
            self.setCursor(QtCore.Qt.WaitCursor)
            self.te_raw.setPlainText("正在解析 APK，请稍候…")
        else:
            self.unsetCursor()

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
        pix = None
        if apk_path and os.path.isfile(apk_path):
            try:
                icons = info.get("icons", {})
                if icons:
                    # 选择最大 density 的 icon
                    best = max(icons.items(), key=lambda x: int(x[0]))
                    icon_path = best[1]

                    self.icon_label.clear()  # 先清空（含上次失败提示文本）
                    self.icon_thread = IconWorker(self.apk_path_edit.text().strip(), icon_path)
                    self.icon_thread.finished.connect(self.on_icon_loaded)
                    self.icon_thread.failed.connect(self.on_icon_failed)
                    self.icon_thread.start()
            except Exception as e:
                print("提取图标失败:", e)

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
        try:
            os.rename(old_path, new_path)
            QtWidgets.QMessageBox.information(self, "完成", f"已重命名为:\n{new_path}")
            self.apk_path_edit.setText(new_path)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"重命名失败: {e}")

    def on_icon_loaded(self, pix: QtGui.QPixmap, data: bytes):
        self.icon_label.setPixmap(pix)
        if pix and not pix.isNull():
            self._current_icon_bytes = data
            self.btn_export_icon.setVisible(True)
        else:
            self._current_icon_bytes = None
            self.btn_export_icon.setVisible(False)

    def on_icon_failed(self, message: str):
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
            "版本: 1.0.1<br>"
            "Copyright (c) 2025 Sinryou.<br>At MIT License."
        )

def main():
    # macOS Retina / 高分屏适配：必须在 QApplication 创建之前设置。
    if sys.platform != "win32":
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
