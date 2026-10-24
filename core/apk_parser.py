# -*- coding: utf-8 -*-
"""APK 图标寻址、自适应图层合成、badging 解析与名称净化。"""
import os
import re
import io
import logging
from PIL import Image

from core.aapt import run_aapt2_dump_xmltree
from core.colors import FRAMEWORK_COLOR_MAP, parse_android_color
from core.resources import (
    entry_span, extract_resource_entry, density_of,
    pick_best_density, sniff_file_kind, get_resource_info,
    BITMAP_EXTS, MAX_DEREF_DEPTH, open_apk_zip
)
from core.vector import rasterize_vector_layer

ICON_SIZE = 512
# 中文标签优先级：简中/新加坡、港澳台/繁体；当只有 zh-Hans、zh-Hant、
# zh-MO 或裸 zh 时也必须优先于通用英文 application-label。
CHINESE_LOCALE_PRIORITY = (
    "zh-CN", "zh-Hans", "zh-SG",
    "zh-HK", "zh-MO", "zh-TW", "zh-Hant",
)

# badging 的字符串值包在单引号里，值内的 ' 与 \ 会被 aapt2 转义成 \' 与 \\。
# [^']* 在转义引号处提前截断：含撇号的值（如 versionName='It\'s'）会被剪断，
# 甚至把后续字段吞进匹配。badging 里所有单引号值统一用本模式取值，
# 再经 _unescape_badging_value 还原。
_BADGING_QUOTED = r"'((?:[^'\\]|\\.)*)'"


def _unescape_badging_value(value: str) -> str:
    """还原 aapt2 badging 单引号字符串值的转义（\\' → '，\\\\ → \\）。"""
    return re.sub(r"\\(.)", r"\1", value)

# Windows 保留设备名不能作为文件名（含带扩展名的形式，如 CON.apk）
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# 单个文件名分量的保守上限。Windows 组件上限是 255，但重命名/导出默认
# 落在 APK 所在目录，长目录下仍可能触发 MAX_PATH；120 字符足够容纳常见
# "应用名_版本号"，也避免恶意超长 label 生成无法创建的文件名。
_MAX_FILENAME_CHARS = 120

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


def _resolve_xml_wrapper(apk_path: str, full_res: str, xml_path: str, depth: int, index=None, zf=None):
    """
    若 xml_path 指向 <scale>/<layer-list> 等包装 drawable，且其 android:drawable
    引用了另一个资源，则跟随引用继续解析（<scale> 的缩放参数一并带回）。
    根元素是纯 <vector> 或找不到引用时返回 (None, None, None)。
    """
    xml_out = run_aapt2_dump_xmltree(apk_path, xml_path)
    if not xml_out:
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
    kind, value, scale2 = resolve_icon_layer(apk_path, full_res, m.group(1), depth + 1, index, zf=zf)
    if not kind:
        return (None, None, None)
    return (kind, value, scale or scale2)


def resolve_icon_layer(apk_path: str, full_res: str, res_id: str, depth: int = 0, index=None, zf=None):
    """
    把一个图标层资源完整解析成可渲染形态：
        ("color", "#AARRGGBB", None)
        ("image", "res/...png", None)
        ("vector", "res/...xml", None)   # 矢量 drawable，交 rasterize_vector_layer 栅格化
        (None, None, None)               # 无法解析
    scale 参数 (width%, height%, gravity) 来自 <scale> 包装。

    支持混淆包的解引用链：字符串值指向文件、无扩展名文件按魔数识别、
    <scale> 包装继续跟随 android:drawable 引用；深度受限防止循环。
    另外支持 Android 框架资源引用（0x01xxxxxx，如 @android:color/transparent）
    以及应用内资源别名——`() @0x7f......`（数字形式）与 `() @color/......`
    （aapt2 2.20+ 的命名形式，如 pixiv 6.201 的 adaptive 背景）都能跟随。
    index 为 ResourceIndex 时条目查询 O(1)。支持传入已有 zf 句柄以复用 I/O。
    """
    rid = (res_id or "").lower()
    if rid.startswith("0x01"):
        # 框架资源（android 包）：资源表里没有，走内置颜色表
        if rid in FRAMEWORK_COLOR_MAP:
            return ("color", FRAMEWORK_COLOR_MAP[rid], None)
        if rid.startswith("0x0106"):  # 框架 color 类型
            return ("color", "#00000000", None)  # 未知框架颜色按透明处理
        return (None, None, None)
    info = get_resource_info(extract_resource_entry(full_res, res_id, index))
    kind, value = info["type"], info["value"]
    if kind in ("color", "image"):
        return (kind, value, None)
    if depth >= MAX_DEREF_DEPTH:
        return ("vector", value, None) if kind == "vector" else (None, None, None)
    if kind == "ref" and value:
        # 应用内别名：继续跟随（目标可能是颜色/位图/矢量，也可能是框架颜色）
        return resolve_icon_layer(apk_path, full_res, value, depth + 1, index, zf=zf)
    if kind == "string_file":
        ext = os.path.splitext(value)[1].lower()
        if ext in BITMAP_EXTS:
            return ("image", value, None)
        if ext == ".xml":
            return _resolve_xml_wrapper(apk_path, full_res, value, depth, index, zf=zf)
        sniffed = sniff_file_kind(apk_path, value, zf=zf)
        if sniffed == "image":
            return ("image", value, None)
        if sniffed == "xml":
            return _resolve_xml_wrapper(apk_path, full_res, value, depth, index, zf=zf)
        return (None, None, None)
    if kind == "vector" and value:
        kind2, value2, scale2 = _resolve_xml_wrapper(apk_path, full_res, value, depth, index, zf=zf)
        if kind2:
            return (kind2, value2, scale2)
        return ("vector", value, None)
    return (None, None, None)


def _collect_bitmap_variants(entry_text: str) -> dict:
    """从资源条目文本收集 {density: 位图路径}。"""
    variants = {}
    for line in (entry_text or "").splitlines():
        m = re.match(r"^\s*\(([^)]*)\)\s*\(file\)\s*(\S+)", line)
        if m and m.group(2).lower().endswith(BITMAP_EXTS):
            variants[density_of(m.group(1))] = m.group(2)
    return variants


def find_mipmap_fallback(full_res: str, icon_xml_path: str, index=None):
    """
    自适应图标（.xml）无法整体栅格化时的回退：
    找到包含该 icon xml 的资源条目（通常是 mipmap/ic_launcher），
    返回其最高密度的位图变体路径（即 8.0 之前使用的传统回退图标）。
    传入 index（ResourceIndex）时 O(1) 查询。
    """
    if index is not None:
        entry = index.by_file.get(icon_xml_path)
        if entry is None:
            return None
        return pick_best_density(_collect_bitmap_variants(entry))

    lines = (full_res or "").splitlines()
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
    a, b = entry_span(lines, start)
    return pick_best_density(_collect_bitmap_variants("\n".join(lines[a:b])))



def load_resource(apk_path, res_path_or_color, size, full_res=None, index=None, zf=None):
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
    with open_apk_zip(apk_path, zf) as apk:
        with apk.open(res_path_or_color["value"]) as f:
            img = Image.open(f).convert("RGBA")
    return img.resize((size, size), Image.LANCZOS)


def to_png_bytes(img) -> bytes:
    """RGBA Image → PNG 字节（导出与跨线程传递共用）。"""
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def decode_icon_image(raw: bytes):
    """解码任意图标字节，返回 (RGBA Image, 原始格式名大写)；解不了返回 (None, "")。

    显示与导出共用同一次解码：显示直接搬运像素（ui.workers._qimage_from_pil），
    导出交给 normalize_icon_image 归一化，不再各自解一遍。
    """
    try:
        with Image.open(io.BytesIO(raw)) as im:
            fmt = (im.format or "").upper()
            return im.convert("RGBA"), fmt
    except Exception:
        logging.debug("位图图标解码失败，由调用方回退处理", exc_info=True)
        return None, ""


def normalize_icon_image(raw: bytes, im=None, fmt: str = "", size: int = ICON_SIZE):
    """把位图图标统一成 (size×size RGBA Image, 导出用 PNG 字节)。

    位图图标旧实现直接导出 APK 里的原始文件，导出尺寸随资源密度变化，
    与自适应/矢量链路固定的 ICON_SIZE² 不一致：同一个"导出图标"按钮
    对不同 APK 给出不同规格的文件。

    raw 已经是目标尺寸的 PNG 时导出字节原样返回：省掉一整圈 LANCZOS +
    重编码，且导出字节与 APK 内原始文件逐位一致。im/fmt 是调用方为显示
    已做过的 decode_icon_image 结果，传入可避免同一份字节解码两次。
    解码失败返回 (None, b"")。
    """
    if im is None:
        im, fmt = decode_icon_image(raw)
        if im is None:
            return None, b""
    if im.size == (size, size) and fmt == "PNG":
        return im, raw
    img = im.resize((size, size), Image.LANCZOS)
    return img, to_png_bytes(img)


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


def compose_adaptive_icon(apk_path, foreground, background, size=ICON_SIZE, fg_scale=None, full_res=None, index=None, zf=None):
    """
    解析 adaptive icon 的前景和背景并合成，返回 (RGBA Image, 导出用 PNG 字节)。

    fg_scale: (width%, height%, gravity)，来自 <scale> 包装 drawable；
              None 表示前景按整层尺寸渲染。

    返回的 Image 供显示直接转 QImage；PNG 字节供导出。旧实现只返回
    字节流，调用方为了显示还得把 PNG 再解码一遍。
    """
    with open_apk_zip(apk_path, zf) as shared_zf:
        # 加载前景
        foreground_img = load_resource(apk_path, foreground, size, full_res, index, zf=shared_zf)
        # 加载背景
        background_img = load_resource(apk_path, background, size, full_res, index, zf=shared_zf)

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
        return final_img, to_png_bytes(final_img)

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
    # package 行的属性顺序随 aapt2 版本变化（如 versionCodeMajor 可能插在
    # versionCode 与 versionName 之间），整行一次性匹配会让包名与版本号
    # 全部丢失；先截取 package 行，再逐个属性独立提取。
    # 所有单引号值统一用支持转义的引号模式取值：versionName 等自由字符串
    # 含撇号时 aapt2 写作 \'，裸 [^']+ 会在转义引号处提前截断。
    m_pkg = re.search(r"package:\s[^\n]*", text)
    if m_pkg:
        pkg_line = m_pkg.group(0)
        m_name = re.search(r"\bname=" + _BADGING_QUOTED, pkg_line)
        if m_name:
            info["package_name"] = _unescape_badging_value(m_name.group(1))
        m_vcode = re.search(r"\bversionCode=" + _BADGING_QUOTED, pkg_line)
        if m_vcode:
            info["version_code"] = _unescape_badging_value(m_vcode.group(1))
        m_vname = re.search(r"\bversionName=" + _BADGING_QUOTED, pkg_line)
        if m_vname:
            info["version_name"] = _unescape_badging_value(m_vname.group(1))

    # 平台/编译 SDK
    m_plat = re.search(r"platformBuildVersionName=" + _BADGING_QUOTED, text)
    if m_plat:
        info["platform_build_version_name"] = _unescape_badging_value(m_plat.group(1))

    m_platc = re.search(r"platformBuildVersionCode=" + _BADGING_QUOTED, text)
    if m_platc:
        info["platform_build_version_code"] = _unescape_badging_value(m_platc.group(1))

    m_compile = re.search(r"compileSdkVersion=" + _BADGING_QUOTED, text)
    if m_compile:
        info["compile_sdk_version"] = _unescape_badging_value(m_compile.group(1))

    m_compile_code = re.search(r"compileSdkVersionCodename=" + _BADGING_QUOTED, text)
    if m_compile_code:
        info["compile_sdk_codename"] = _unescape_badging_value(m_compile_code.group(1))

    # Sdk 版本
    m_min = re.search(r"minSdkVersion:" + _BADGING_QUOTED, text)
    if m_min:
        info["min_sdk"] = _unescape_badging_value(m_min.group(1))
    m_target = re.search(r"targetSdkVersion:" + _BADGING_QUOTED, text)
    if m_target:
        info["target_sdk"] = _unescape_badging_value(m_target.group(1))

    # --- 应用名（多语言） ---
    for loc, label in re.findall(r"application-label-([\w-]+):" + _BADGING_QUOTED, text):
        info["app_name_labels"][loc] = _unescape_badging_value(label)

    # 通用标签
    m_label_generic = re.search(r"application-label:" + _BADGING_QUOTED, text)
    generic_label = _unescape_badging_value(m_label_generic.group(1)) if m_label_generic else ""

    # application 节点的 label
    m_label_app = re.search(r"application:\s+label=" + _BADGING_QUOTED, text)
    app_node_label = _unescape_badging_value(m_label_app.group(1)) if m_label_app else ""

    # 选择优先中文：locale 统一按 "-" 连接、大小写不敏感匹配。
    # aapt2 通常输出 zh-CN / zh-Hans；部分工具或手写测试可能用下划线。
    labels_lower = {
        loc.replace("_", "-").lower(): label
        for loc, label in info["app_name_labels"].items()
    }
    for pref in CHINESE_LOCALE_PRIORITY:
        if labels_lower.get(pref.lower()):
            info["app_name"] = labels_lower[pref.lower()]
            break
    if not info["app_name"]:
        # 任意中文变体（zh、zh-Hans-CN、zh-MO…）都优先于通用英文标签。
        # 旧实现把 generic 放在 zh 前面，只有 application-label-zh 的包
        # 会显示英文名；zh-Hans/zh-Hant 则完全被忽略。
        zh_label = next(
            (label for loc, label in labels_lower.items()
             if (loc == "zh" or loc.startswith("zh-")) and label),
            "",
        )
        info["app_name"] = zh_label or generic_label or app_node_label

    # --- 可启动 Activity ---
    m_launch = re.search(r"launchable-activity:\s+name=" + _BADGING_QUOTED, text)
    if m_launch:
        info["launchable_activity"] = _unescape_badging_value(m_launch.group(1))

    # --- 权限 ---
    # 支持 uses-permission 与 uses-permission-sdk-23，保持顺序去重并支持转义单引号
    perms = []
    for p in re.findall(r"uses-permission(?:-sdk-23)?:\s+name=" + _BADGING_QUOTED, text):
        cleaned = _unescape_badging_value(p)
        if cleaned not in perms:
            perms.append(cleaned)
    info["permissions"] = perms

    # --- Feature ---
    info["features"] = [
        _unescape_badging_value(v)
        for v in re.findall(r"uses-feature:\s+name=" + _BADGING_QUOTED, text)
    ]
    info["implied_features"] = [
        _unescape_badging_value(v)
        for v in re.findall(r"uses-implied-feature:\s+name=" + _BADGING_QUOTED, text)
    ]

    # --- 支持屏幕/密度/语言（一行内的一串单引号值） ---
    def _quoted_list(prefix: str) -> list:
        m = re.search(prefix + r"\s+((?:" + _BADGING_QUOTED + r"\s*)+)", text)
        if not m:
            return []
        return [_unescape_badging_value(v) for v in re.findall(_BADGING_QUOTED, m.group(1))]

    info["supports_screens"] = _quoted_list(r"supports-screens:")
    info["densities"] = _quoted_list(r"densities:")
    info["locales"] = _quoted_list(r"locales:")

    m_anyden = re.search(r"supports-any-density:\s+" + _BADGING_QUOTED, text)
    if m_anyden:
        info["supports_any_density"] = _unescape_badging_value(m_anyden.group(1))

    # --- 图标（按密度） ---
    for dens, path_ in re.findall(r"application-icon-([0-9]+):" + _BADGING_QUOTED, text):
        info["icons"][dens] = _unescape_badging_value(path_)

    # 少数 APK 没有 application-icon-* 行，只在 application 节点上有 icon 属性，
    # 此前这种情况会完全不显示图标。用"密度"0 占位，fill_info 取 max() 挑选
    # 最佳密度时不会被它盖过真实密度。
    if not info["icons"]:
        m_icon = re.search(r"^application:\s[^\n]*?icon=" + _BADGING_QUOTED, text, re.M)
        if m_icon and m_icon.group(1):
            info["icons"]["0"] = _unescape_badging_value(m_icon.group(1))

    # --- 支持架构 ---
    archs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("native-code:") or line.startswith("alt-native-code:"):
            for arch in re.findall(r"'([^']+)'", line):
                # native-code 与 alt-native-code 常重复列出同一架构，按出现顺序去重
                if arch not in archs:
                    archs.append(arch)
    info["architectures"] = archs

    return info


def pick_best_icon(icons: dict) -> str:
    """从 badging 的 {density: 路径} 中选最高密度的图标路径，空表返回空串。

    密度键是十进制数字字符串（自适应图标的 anydpi 变体密度值最大），
    按数值比较即可。--self-test 与主窗口 fill_info 共用本逻辑。
    """
    if not icons:
        return ""
    return max(icons.items(), key=lambda item: int(item[0]))[1]


def sanitize_filename(name: str, ext: str = "") -> str:
    """把应用名/文件名整理成合法的 Windows 文件名（可选指定扩展名）。

    - 非法字符（\\ / : * ? " < > | 与控制字符）替换为下划线；
    - 去掉结尾的点和空格：Windows 会静默丢弃它们，生成的文件名与预期不符；
    - 保留设备名（CON / NUL / COM1 …）加下划线前缀规避；
    - 若指定 ext，先去除已有相同扩展名，最后统一附上指定扩展名；
    - 全部被清理掉时返回空串。
    """
    stem = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", (name or "").strip())
    if ext:
        ext_clean = ext if ext.startswith(".") else f".{ext}"
        if stem.lower().endswith(ext_clean.lower()):
            stem = stem[:-len(ext_clean)]
    else:
        ext_clean = ""
    stem = stem.rstrip(" .")
    if not stem:
        return ""
    # 超长 label 不能让重命名/导出生成 Windows 无法创建的文件名。
    # 预留扩展名长度，按字符截断；截断后再去掉尾部点/空格。
    max_stem = max(1, _MAX_FILENAME_CHARS - len(ext_clean))
    if len(stem) > max_stem:
        stem = stem[:max_stem].rstrip(" .")
        if not stem:
            return ""
    if stem.upper() in _RESERVED_NAMES:
        stem = "_" + stem
        stem = stem[:max_stem].rstrip(" .")
        if not stem:
            return ""
    return stem + ext_clean


def sanitize_apk_name(name: str) -> str:
    """把应用名/用户输入整理成合法的 APK 文件名（含 .apk 扩展名）。

    - 非法字符（\\ / : * ? " < > | 与控制字符）替换为下划线；
    - 去掉结尾的点和空格：Windows 会静默丢弃它们，生成的文件名与预期不符；
    - 保留设备名（CON / NUL / COM1 …）加下划线前缀规避；
    - 全部被清理掉时返回空串，由调用方提示"没有生成新的文件名"。
    """
    return sanitize_filename(name, ext=".apk")


