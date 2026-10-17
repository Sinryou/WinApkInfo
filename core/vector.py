# -*- coding: utf-8 -*-
"""Android VectorDrawable 矢量图解析与光栅化引擎。"""
import math
import re
import io
import logging
from PIL import Image, ImageChops, ImageDraw

try:
    import numpy as np
except ImportError:
    np = None

from core.aapt import run_aapt2_dump_xmltree, run_aapt2_dump_resource
from core.colors import _FRAMEWORK_COLOR_MAP, parse_android_color
from core.resources import (
    _ResourceIndex, extract_resource_entry, get_resource_info, _MAX_DEREF_DEPTH
)
from PyQt6 import QtCore, QtGui

# strokeLineCap 同样是枚举：aapt2 输出十进制 0=butt / 1=round / 2=square。
# 查表前先用 _attr_enum 归一化，否则圆头/方头端点会被静默降级成 butt
# （旧表只有名字和 0x 写法两种键，命中不了十进制值）。
_VECTOR_CAPS = {"butt": 0, "round": 1, "square": 2, "0": 0, "1": 1, "2": 2}


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


def _attr_enum(raw) -> str:
    """把 aapt2 的枚举型属性值归一化成小写字符串。

    `aapt2 dump xmltree` 对枚举属性一律输出**十进制**整数（实测
    fillType=1 / strokeLineCap=2 / gradient type=1），个别版本可能输出
    0x00000001。这里统一折算成十进制字符串，调用方既可以按名字
    （"evenodd"）也可以按数值（"1"）比较；无法识别时返回小写原值。
    """
    v = str(raw if raw is not None else "").strip().lower()
    if v.startswith("0x"):
        try:
            return str(int(v, 16))
        except ValueError:
            return v
    return v


def _attr_int(raw, default: int = 0) -> int:
    """把 aapt2 的枚举型属性值取整，十进制与 0x 写法都能识别。

    必须走 _attr_enum 而不是 _attr_float：后者的正则 `^([-+0-9.eE]+)` 遇到
    `0x00000001` 只会匹配到开头的 `0`，枚举值会被静默解析成 0。
    """
    try:
        return int(_attr_enum(raw))
    except (TypeError, ValueError):
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
            try:
                tokens.append((None, float(d[i:j])))
            except ValueError:
                # 畸形数字（如 "1.2.3"）：跳过该记号，而不是让整条 pathData
                # 解析失败、把整个图标判为提取失败。
                logging.debug("pathData 中的非法数字已跳过: %r", d[i:j])
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
            last_cmd = c.upper()
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
            last_cmd = c.upper()
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
        # 统一存大写：S/T 分支要判断「上一条命令是不是 C/S」「Q/T」，
        # 存原始大小写会让相对命令 c/q 后的 s/t 判不出镜像控制点。
        last_cmd = c.upper()
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


def _mat_scale(m):
    """仿射矩阵的平均缩放倍数 = sqrt(|det|)，用于把 viewport 单位换算成像素。

    描边宽度必须跟着 **group 变换** 一起缩放：aapt2 里 group 的 scaleX/scaleY
    会把 path 坐标整体缩小（实测 GhostLock 的 group scale=0.0586），若只乘
    viewport→像素的全局比例，strokeWidth 会被放大约 17 倍，细线变成实心块。
    非等比缩放下 Android 的描边本身是各向异性的，这里用面积的平方根做近似。
    """
    return math.sqrt(abs(m[0] * m[3] - m[1] * m[2]))


def _group_matrix(tx, ty, px, py, rot_deg, sx, sy):
    """VectorDrawable group 变换：T(translate+pivot) ∘ R(rot) ∘ S(scale) ∘ T(-pivot)。"""
    r = math.radians(rot_deg)
    cosr, sinr = math.cos(r), math.sin(r)
    R = (cosr, sinr, -sinr, cosr, 0.0, 0.0)
    S = (sx, 0.0, 0.0, sy, 0.0, 0.0)
    Tm = (1.0, 0.0, 0.0, 1.0, -px, -py)
    Tp = (1.0, 0.0, 0.0, 1.0, tx + px, ty + py)
    return _mat_mul(Tp, _mat_mul(R, _mat_mul(S, Tm)))


# 填充掩码分块行数：限制 (行数 × 边数) 中间矩阵的内存占用
_MASK_CHUNK_ROWS = 128


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

    按 _MASK_CHUNK_ROWS 行分块：中间矩阵规模是 (行数 × 边数)，一次对整幅图
    做广播时，2 万条边在 1024² 画布上峰值内存接近 500MB；分块后只与当前
    行区间相交的边参与运算，结果完全一致。
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

    y_min = np.minimum(y1, y2)
    y_max = np.maximum(y1, y2)
    wnd = np.where(y2 > y1, 1.0, -1.0)

    for chunk_lo in range(y_lo, y_hi, _MASK_CHUNK_ROWS):
        chunk_hi = min(chunk_lo + _MASK_CHUNK_ROWS, y_hi)
        ys = np.arange(chunk_lo, chunk_hi) + 0.5
        # 预筛：只有 y 区间与本块重叠的边才可能相交（宽松上界，不影响结果）
        sel = (y_min < chunk_hi) & (y_max > chunk_lo)
        if not sel.any():
            continue
        bx1, bx2, by1, by2 = x1[sel], x2[sel], y1[sel], y2[sel]
        # 每条边在每个扫描线是否相交（半开规则）
        cross = ((by1 <= ys[:, None]) & (ys[:, None] < by2)) | ((by2 <= ys[:, None]) & (ys[:, None] < by1))
        t = (ys[:, None] - by1[None, :]) / (by2[None, :] - by1[None, :])
        xs = np.where(cross, bx1[None, :] + t * (bx2[None, :] - bx1[None, :]), np.nan)
        bwnd = wnd[sel]

        for r in range(len(ys)):
            row = xs[r]
            keep = ~np.isnan(row)
            if not keep.any():
                continue
            row = row[keep]
            y = chunk_lo + r
            if fill_rule == "evenodd":
                row.sort()
                starts = row[0::2]
                ends = row[1::2]
            else:
                wrow = bwnd[keep]
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


def _parse_gradient(xml_out, resolve_color=None):
    """解析 aapt2 拆分出来的 <gradient> drawable（$xxx__0.xml），失败返回 None。

    resolve_color: 可选的颜色解析回调，用于把 ``@0x7f...`` 这类资源引用
    解析成 RGBA。渐变颜色既可能写成 ``#AARRGGBB``，也可能是
    ``@color/...``；后者在 xmltree 里只留资源地址，需要调用方补解析。
    """
    elems = _parse_vector_elements(xml_out)
    if not elems or elems[0]["tag"] != "gradient":
        return None
    attrs = elems[0]["attrs"]

    def _color(raw):
        """解析 #hex 或经回调解析资源引用；失败返回 None。"""
        if not raw:
            return None
        try:
            return parse_android_color(raw)
        except ValueError:
            pass
        if resolve_color is not None:
            try:
                resolved = resolve_color(raw)
            except Exception as e:
                logging.debug("解析渐变颜色失败 %r: %s", raw, e)
                return None
            if resolved:
                return resolved
        return None

    grad = {
        # type 是枚举：必须走 _attr_int（内部用 _attr_enum），
        # 用 _attr_float 会把 0x00000001 解析成 0 → 径向/扫描渐变退化成线性。
        "type": _attr_int(attrs.get("type"), 0),  # 0=linear 1=radial 2=sweep
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
        c = _color(a["color"])
        if c is None:
            continue
        grad["stops"].append((_attr_float(a, "offset", 0.0), c))
    if not grad["stops"]:
        # Android 的 <gradient> 也支持直接用 startColor / centerColor /
        # endColor 描述颜色（aapt2 xmltree 不会把它们改写成 <item>）。
        # 旧实现只读 <item>，这类渐变会因 stops 为空被整层跳过。
        for name, offset in (("startColor", 0.0), ("centerColor", 0.5), ("endColor", 1.0)):
            c = _color(attrs.get(name))
            if c is not None:
                grad["stops"].append((offset, c))
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


def _linear_gradient_line(W, H, grad, m):
    """返回线性渐变在像素空间的 (sx, sy, dx, dy, dd)。

    显式的 startX/startY/endX/endY 直接经矩阵映射；两者都没有时，
    按 android:angle 在整幅画布上构造一条从一端到另一端的渐变线，
    保证 t 仍覆盖 0..1（0° = 左→右，90° = 下→上）。
    """
    sx, sy = _mat_apply(m, grad["startX"], grad["startY"])
    ex, ey = _mat_apply(m, grad["endX"], grad["endY"])
    dx, dy = ex - sx, ey - sy
    dd = dx * dx + dy * dy
    if dd < 1e-9:
        a = math.radians(grad["angle"])
        ux, uy = math.cos(a), -math.sin(a)
        # 画布在方向向量上的投影长度，保证渐变线覆盖整个画面
        length = max(abs(W * ux) + abs(H * uy), 1.0)
        sx = W / 2.0 - ux * length / 2.0
        sy = H / 2.0 - uy * length / 2.0
        dx, dy = ux * length, uy * length
        dd = length * length
    return sx, sy, dx, dy, dd


def _scale_alpha(img, factor):
    """只缩放 alpha 通道，保持 RGB 不变。

    Pillow 的 ``Image.point`` 对 RGBA 会同时处理四个通道；直接用它乘
    fillAlpha 会把渐变颜色本身也调暗。半透明渐变必须只改 A 通道。
    """
    if factor >= 0.999:
        return img
    r, g, b, a = img.split()
    a = a.point(lambda v: int(round(v * factor)))
    return Image.merge("RGBA", (r, g, b, a))


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
        sx, sy, dx, dy, dd = _linear_gradient_line(W, H, grad, m)
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
        sx, sy, dx, dy, dd = _linear_gradient_line(W, H, grad, m)
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


def _resolve_vector_fill(apk_path, full_res, color_value, index=None, depth=0):
    """
    解析 vector 的 fillColor / strokeColor 属性值（可能带资源引用）。
    返回 ("color", (r,g,b,a))、("gradient", grad_dict) 或 None。

    颜色资源本身也可能是一条别名（`() @0x0106...`，Material You 动态色
    在 APK 里就是这种形态），因此这里要跟随引用链；深度受限防止循环。
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
    if info["type"] == "ref" and info["value"]:
        if depth >= _MAX_DEREF_DEPTH:
            return None
        target = info["value"].lower()
        if target.startswith("0x01"):
            c = _FRAMEWORK_COLOR_MAP.get(target)
            if c:
                try:
                    return ("color", parse_android_color(c))
                except ValueError:
                    return None
            return None
        return _resolve_vector_fill(apk_path, full_res, "@" + target, index, depth + 1)
    if info["type"] in ("vector", "string_file", "image") and info["value"]:
        # 可能是 aapt2 拆分出来的渐变 drawable（$xxx__0.xml）
        grad = _parse_gradient(
            run_aapt2_dump_xmltree(apk_path, info["value"]),
            resolve_color=lambda raw: _resolve_gradient_color(
                apk_path, full_res, raw, index, depth
            ),
        )
        if grad:
            return ("gradient", grad)
    return None


def _resolve_gradient_color(apk_path, full_res, value, index=None, depth=0):
    """把渐变的 startColor/centerColor/endColor 解析成 RGBA。

    渐变颜色可能是资源引用，_parse_gradient 本身只认识 #hex；
    这里复用 _resolve_vector_fill 的引用链解析，并限制递归深度。
    """
    if depth >= _MAX_DEREF_DEPTH:
        return None
    try:
        resolved = _resolve_vector_fill(apk_path, full_res, value, index, depth + 1)
    except Exception as e:
        logging.debug("解析渐变颜色失败 %r: %s", value, e)
        return None
    if resolved and resolved[0] == "color":
        return resolved[1]
    return None


def _extend_square_caps(pts, half):
    """把折线首尾点沿首/末线段方向各外推 half，得到 square 端点所需的延长线。

    闭合子路径（首尾重合）没有端点，原样返回。方向为零长度时也不动，
    避免除零。
    """
    if len(pts) < 2:
        return list(pts)
    start, second = pts[0], pts[1]
    end, prev = pts[-1], pts[-2]
    if abs(start[0] - end[0]) < 1e-9 and abs(start[1] - end[1]) < 1e-9:
        return list(pts)  # 闭合子路径
    out = list(pts)
    d0 = math.hypot(second[0] - start[0], second[1] - start[1])
    if d0 > 1e-9:
        out[0] = (start[0] - (second[0] - start[0]) / d0 * half,
                  start[1] - (second[1] - start[1]) / d0 * half)
    d1 = math.hypot(prev[0] - end[0], prev[1] - end[1])
    if d1 > 1e-9:
        out[-1] = (end[0] - (prev[0] - end[0]) / d1 * half,
                   end[1] - (prev[1] - end[1]) / d1 * half)
    return out


def _stroke_mask(size, subpaths, wpx, cap):
    """把描边路径画到 L 模式掩码上，供纯色/渐变描边共用。

    butt(0) 原样、round(1) 两端补圆、square(2) 沿首末线段方向各延长半个
    线宽（等价于方形端点）。
    """
    mask = Image.new("L", size, 0)
    d = ImageDraw.Draw(mask)
    r = wpx / 2.0
    for pts in subpaths:
        if len(pts) < 2:
            continue
        draw_pts = _extend_square_caps(pts, r) if cap == 2 else pts
        d.line([(round(p[0]), round(p[1])) for p in draw_pts], fill=255, width=wpx, joint="curve")
        if cap == 1:  # round
            for p in (pts[0], pts[-1]):
                d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=255)
    return mask


def _draw_stroke(layer, subpaths, color, alpha, wpx, cap):
    """描边一条路径，端点按 strokeLineCap 处理。

    拐角统一用 Pillow 的 round join 近似：ImageDraw 不提供 miter/bevel，
    Android 默认的 miter 在尖锐折角处会比这里略"尖"，属已知近似。
    """
    if alpha <= 0 or color[3] <= 0:
        return
    mask = _stroke_mask(layer.size, subpaths, wpx, cap)
    if alpha < 0.999:
        mask = mask.point(lambda v: int(round(v * alpha)))
    if color[3] < 255:
        mask = mask.point(lambda v: int(round(v * color[3] / 255.0)))
    # 只把覆盖率写进 alpha 通道，RGB 保持描边原色；
    # 不能用 Image.composite(tint, transparent, mask)，否则 RGB 会被一起
    # 拉向透明黑，半透明描边会变暗。
    tint = Image.new("RGBA", layer.size, (color[0], color[1], color[2], 255))
    tint.putalpha(mask)
    layer.alpha_composite(tint)


def _qimage_to_pil(qimg: QtGui.QImage) -> Image.Image:
    """把 QImage 转为 PIL RGBA Image。"""
    if qimg.isNull():
        return None
    converted = qimg.convertToFormat(QtGui.QImage.Format.Format_RGBA8888)
    w, h = converted.width(), converted.height()
    b = converted.bits()
    b.setsize(w * h * 4)
    return Image.frombuffer("RGBA", (w, h), bytes(b), "raw", "RGBA", 0, 1)


def _create_qbrush(fill, m, falpha: float, width=None, height=None):
    """根据解析后的 fill ('color' 或 'gradient') 创建对应的 QBrush。

    width/height 是目标画布尺寸：只有 angle、没有 start/end 的线性渐变
    需要借助画布尺寸构造覆盖整幅图的渐变线。
    """
    if fill[0] == "color":
        c = fill[1]
        ca = int(round(c[3] * falpha))
        if ca <= 0:
            return None
        return QtGui.QBrush(QtGui.QColor(c[0], c[1], c[2], ca))

    if fill[0] == "gradient":
        grad = fill[1]
        gt = grad["type"]
        if gt == 0:  # linear
            if width is not None and height is not None:
                sx, sy, dx, dy, _dd = _linear_gradient_line(width, height, grad, m)
                ex, ey = sx + dx, sy + dy
            else:
                sx, sy = _mat_apply(m, grad["startX"], grad["startY"])
                ex, ey = _mat_apply(m, grad["endX"], grad["endY"])
                if (ex - sx) ** 2 + (ey - sy) ** 2 < 1e-9:
                    a = math.radians(grad["angle"])
                    ex, ey = sx + math.cos(a) * 1000.0, sy - math.sin(a) * 1000.0
            qgrad = QtGui.QLinearGradient(QtCore.QPointF(sx, sy), QtCore.QPointF(ex, ey))
        elif gt == 1:  # radial
            cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
            det = m[0] * m[3] - m[1] * m[2]
            r_px = grad["radius"] * math.sqrt(abs(det)) if det else grad["radius"]
            qgrad = QtGui.QRadialGradient(QtCore.QPointF(cx, cy), max(1e-3, r_px))
        else:  # sweep
            cx, cy = _mat_apply(m, grad["centerX"], grad["centerY"])
            qgrad = QtGui.QConicalGradient(QtCore.QPointF(cx, cy), 180.0)

        for offset, color in grad["stops"]:
            ca = int(round(color[3] * falpha))
            qgrad.setColorAt(offset, QtGui.QColor(color[0], color[1], color[2], ca))
        return QtGui.QBrush(qgrad)

    return None


def _cmds_to_qpainterpath(cmds, m, fill_rule="nonzero", step=1.0) -> QtGui.QPainterPath:
    """把 SVG path 命令直接构造成 Qt 原生 QPainterPath，利用 C++ 原生三次/二次贝塞尔与圆弧渲染。"""
    qpath = QtGui.QPainterPath()
    qpath.setFillRule(
        QtCore.Qt.FillRule.OddEvenFill if fill_rule == "evenodd" else QtCore.Qt.FillRule.WindingFill
    )
    cur = [0.0, 0.0]
    start = [0.0, 0.0]
    last_cmd = None
    last_ctrl = None

    for cmd, args in cmds:
        c = cmd
        if c in ("Z", "z"):
            qpath.closeSubpath()
            cur = [start[0], start[1]]
            last_cmd = "Z"
            last_ctrl = None
            continue

        if c in ("M", "m"):
            x, y = args[0], args[1]
            if c == "m":
                x += cur[0]
                y += cur[1]
            cur = [x, y]
            start = [x, y]
            tx, ty = _mat_apply(m, x, y)
            qpath.moveTo(tx, ty)
            last_cmd = "M"
            last_ctrl = None
            continue

        rel = c.islower()
        base = c.upper()
        if base == "L":
            for k in range(0, len(args), 2):
                x, y = args[k], args[k + 1]
                if rel:
                    x += cur[0]
                    y += cur[1]
                cur = [x, y]
                tx, ty = _mat_apply(m, x, y)
                qpath.lineTo(tx, ty)
            last_cmd = "L"
            last_ctrl = None
        elif base == "H":
            for k in range(len(args)):
                x = args[k]
                if rel:
                    x += cur[0]
                cur = [x, cur[1]]
                tx, ty = _mat_apply(m, cur[0], cur[1])
                qpath.lineTo(tx, ty)
            last_cmd = "H"
            last_ctrl = None
        elif base == "V":
            for k in range(len(args)):
                y = args[k]
                if rel:
                    y += cur[1]
                cur = [cur[0], y]
                tx, ty = _mat_apply(m, cur[0], cur[1])
                qpath.lineTo(tx, ty)
            last_cmd = "V"
            last_ctrl = None
        elif base == "C":
            for k in range(0, len(args), 6):
                x1, y1, x2, y2, x, y = args[k:k + 6]
                if rel:
                    x1 += cur[0]; y1 += cur[1]; x2 += cur[0]; y2 += cur[1]; x += cur[0]; y += cur[1]
                p1 = _mat_apply(m, x1, y1)
                p2 = _mat_apply(m, x2, y2)
                p = _mat_apply(m, x, y)
                qpath.cubicTo(p1[0], p1[1], p2[0], p2[1], p[0], p[1])
                cur = [x, y]
                last_ctrl = (x2, y2)
            last_cmd = "C"
        elif base == "S":
            for k in range(0, len(args), 4):
                x2, y2, x, y = args[k:k + 4]
                if rel:
                    x2 += cur[0]; y2 += cur[1]; x += cur[0]; y += cur[1]
                if last_cmd in ("C", "S") and last_ctrl is not None:
                    x1, y1 = 2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1]
                else:
                    x1, y1 = cur[0], cur[1]
                p1 = _mat_apply(m, x1, y1)
                p2 = _mat_apply(m, x2, y2)
                p = _mat_apply(m, x, y)
                qpath.cubicTo(p1[0], p1[1], p2[0], p2[1], p[0], p[1])
                cur = [x, y]
                last_ctrl = (x2, y2)
            last_cmd = "S"
        elif base == "Q":
            for k in range(0, len(args), 4):
                x1, y1, x, y = args[k:k + 4]
                if rel:
                    x1 += cur[0]; y1 += cur[1]; x += cur[0]; y += cur[1]
                p1 = _mat_apply(m, x1, y1)
                p = _mat_apply(m, x, y)
                qpath.quadTo(p1[0], p1[1], p[0], p[1])
                cur = [x, y]
                last_ctrl = (x1, y1)
            last_cmd = "Q"
        elif base == "T":
            for k in range(0, len(args), 2):
                x, y = args[k], args[k + 1]
                if rel:
                    x += cur[0]; y += cur[1]
                if last_cmd in ("Q", "T") and last_ctrl is not None:
                    x1, y1 = 2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1]
                else:
                    x1, y1 = cur[0], cur[1]
                p1 = _mat_apply(m, x1, y1)
                p = _mat_apply(m, x, y)
                qpath.quadTo(p1[0], p1[1], p[0], p[1])
                cur = [x, y]
                last_ctrl = (x1, y1)
            last_cmd = "T"
        elif base == "A":
            for k in range(0, len(args), 7):
                rx, ry, rot, large, sweep, x, y = args[k:k + 7]
                if rel:
                    x += cur[0]; y += cur[1]
                arc_pts = _arc_points(cur[0], cur[1], rx, ry, rot, large != 0, sweep != 0, x, y, step)
                for pt in arc_pts:
                    tp = _mat_apply(m, pt[0], pt[1])
                    qpath.lineTo(tp[0], tp[1])
                cur = [x, y]
                last_ctrl = None
            last_cmd = "A"

    return qpath


def _rasterize_vector_layer_qt(apk_path, xml_path, size, full_res=None, index=None):
    """使用 PyQt6 原生 QPainterPath / QPainter 进行 C++ 矢量光栅化。"""
    xml_out = run_aapt2_dump_xmltree(apk_path, xml_path)
    if not xml_out:
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

    W = size
    H = size
    sx = W / vw
    sy = H / vh
    step = max(0.5, max(vw, vh) / 160.0)
    vec_alpha = _attr_float(attrs, "alpha", 1.0)

    qimg = QtGui.QImage(W, H, QtGui.QImage.Format.Format_ARGB32_Premultiplied)
    qimg.fill(QtCore.Qt.GlobalColor.transparent)
    painter = QtGui.QPainter(qimg)
    painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform, True)

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
            if not cmds:
                continue
            m = _mat_mul((sx, 0.0, 0.0, sy, 0.0, 0.0), pm)
            fill_rule = "evenodd" if _attr_enum(a.get("fillType")) in ("1", "evenodd") else "nonzero"
            qpath = _cmds_to_qpainterpath(cmds, m, fill_rule, step)
            if qpath.isEmpty():
                continue

            if "fillColor" in a:
                fill = _resolve_vector_fill(apk_path, full_res, a["fillColor"], index)
                if fill is not None:
                    falpha = pa * _attr_float(a, "fillAlpha", 1.0)
                    brush = _create_qbrush(fill, m, falpha, W, H)
                    if brush is not None:
                        painter.fillPath(qpath, brush)

            if "strokeColor" in a:
                sc = _resolve_vector_fill(apk_path, full_res, a["strokeColor"], index)
                if sc is not None:
                    sw = _attr_float(a, "strokeWidth", 0.0)
                    sa = pa * _attr_float(a, "strokeAlpha", 1.0)
                    if sw > 0 and sa > 0:
                        wpx = max(1.0, sw * _mat_scale(m))
                        cap_enum = _attr_enum(a.get("strokeLineCap", "butt"))
                        if cap_enum in ("1", "round"):
                            cap = QtCore.Qt.PenCapStyle.RoundCap
                        elif cap_enum in ("2", "square"):
                            cap = QtCore.Qt.PenCapStyle.SquareCap
                        else:
                            cap = QtCore.Qt.PenCapStyle.FlatCap

                        join_enum = _attr_enum(a.get("strokeLineJoin", "round"))
                        if join_enum in ("0", "miter"):
                            join = QtCore.Qt.PenJoinStyle.MiterJoin
                        elif join_enum in ("2", "bevel"):
                            join = QtCore.Qt.PenJoinStyle.BevelJoin
                        else:
                            join = QtCore.Qt.PenJoinStyle.RoundJoin

                        pen = QtGui.QPen()
                        pen.setWidthF(wpx)
                        pen.setCapStyle(cap)
                        pen.setJoinStyle(join)
                        brush = _create_qbrush(sc, m, sa, W, H)
                        if brush is not None:
                            pen.setBrush(brush)
                            painter.strokePath(qpath, pen)

    painter.end()
    return _qimage_to_pil(qimg)


def _rasterize_vector_layer_pil(apk_path, xml_path, size, full_res=None, index=None):
    """纯 Python/Pillow 栅格化回退实现。"""
    xml_out = run_aapt2_dump_xmltree(apk_path, xml_path)
    if not xml_out:
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
            # fillType 是枚举：aapt2 输出十进制 0=nonZero / 1=evenOdd，
            # 旧实现只与字符串 "evenodd" 比较，导致 evenOdd 路径全部被
            # 当成 nonzero 渲染（同向子路径的"洞"会被填实）。
            fill_rule = "evenodd" if _attr_enum(a.get("fillType")) in ("1", "evenodd") else "nonzero"
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
                        gimg = _scale_alpha(_render_gradient(W, H, fill[1], m), falpha)
                        gimg.putalpha(ImageChops.multiply(gimg.getchannel("A"), mask))
                        layer.alpha_composite(gimg)
            if "strokeColor" in a:
                sc = _resolve_vector_fill(apk_path, full_res, a["strokeColor"], index)
                if sc is not None:
                    sw = _attr_float(a, "strokeWidth", 0.0)
                    sa = pa * _attr_float(a, "strokeAlpha", 1.0)
                    if sw > 0 and sa > 0:
                        # 描边宽度按完整变换（viewport 缩放 × group 缩放/旋转）换算，
                        # 不能只用 sx/sy，否则带 group scale 的图标描边会粗成实心块。
                        wpx = max(1, int(round(sw * _mat_scale(m))))
                        cap = _VECTOR_CAPS.get(_attr_enum(a.get("strokeLineCap", "butt")), 0)
                        if sc[0] == "color":
                            _draw_stroke(layer, tsubs, sc[1], sa, wpx, cap)
                        elif sc[0] == "gradient":
                            mask = _stroke_mask(layer.size, tsubs, wpx, cap)
                            if sa < 0.999:
                                mask = mask.point(lambda v: int(round(v * sa)))
                            gimg = _render_gradient(W, H, sc[1], m)
                            # 只把描边覆盖率写进 alpha，保留渐变 RGB，避免描边发暗
                            gimg.putalpha(ImageChops.multiply(gimg.getchannel("A"), mask))
                            layer.alpha_composite(gimg)
    return layer.resize((size, size), Image.LANCZOS)


def rasterize_vector_layer(apk_path, xml_path, size, full_res=None, index=None):
    """
    把 Android VectorDrawable（aapt2 dump xmltree 输出）栅格化为 size×size RGBA 图像。
    支持 vector / group / path、填充与描边、nonzero/evenodd 填充规则、
    以及带资源引用的填充（含 aapt2 拆分出来的 <gradient> 渐变）。

    优先使用 PyQt6 原生 QPainterPath / QPainter 进行 C++ 矢量光栅化；
    若遇到异常自动平滑回退到 Pillow 渲染链路。
    """
    try:
        return _rasterize_vector_layer_qt(apk_path, xml_path, size, full_res, index)
    except Exception as e:
        logging.warning("Qt 矢量光栅化异常，回退 Pillow 渲染: %s", e)
        return _rasterize_vector_layer_pil(apk_path, xml_path, size, full_res, index)


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

