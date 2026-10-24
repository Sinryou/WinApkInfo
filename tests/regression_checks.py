# -*- coding: utf-8 -*-
"""WinApkInfo 回归检查用例集（由 tests/test_verify.py 的 pytest 用例调用）。

这些检查来自历史提交的修复验证（P0/P1/P2/A/B/C/D 各节），集中放在独立模块里
以复用测试辅助（sample_apks / wait_for / consume_events 等）。执行入口统一为
pytest，不再提供独立脚本：

    python -m pytest tests -q -m "not e2e"   # 不依赖 testSample（CI/构建默认）
    python -m pytest tests -q                # 含端到端（需 testSample/）

覆盖范围（与提交一一对应）：
    P0-1  fillType 枚举（evenOdd 生效）
    P0-2  相对 s/t 命令的平滑控制点镜像
    P0-3  strokeLineCap 十进制枚举
    P1-4  slot 内异常不再终止进程
    P1-5  aapt2 子进程超时 / 可强制结束 / closeEvent 不再 terminate
    P1-6  图标线程重启不阻塞 UI
    P1-7  process_apk(path) 使用传入路径
    P1-8  图标失败为非模态提示
    P2-9  填充掩码分块：结果与旧算法一致且内存大幅下降
    P2-10 aapt2 路径查找被缓存
    P2-11 磁盘级 dump 缓存：跨进程复用，APK 变化即失效
    P2-12 回归守护：Pillow resize 不渗透明背景色（当前 Pillow 已内置预乘，
          该项经复核为误报，故只做守护不复修改代码）
    A1    异常钩子线程安全（子线程不直接弹窗、进程不崩）
    B1    自适应图标层无法栅格化时回退到位图
    B2    磁盘缓存单条与总量字节上限
    B3    SDK 版本表读取失败不再永久缓存
    B4    图标提取为单常驻线程 + 最新请求覆盖
    C     本轮修复回归：渐变 type 枚举 / #RGB 颜色 / 畸形 pathData 容错 /
          strokeLineCap=square / 文件名净化 / dump 失败返回 None /
          统一 512² 导出 / 子线程只用 QImage / 图标与架构兜底
    D1    新一轮解析开始时作废在途图标结果（代数推进 + 核心 cancel）
    D2    aapt2 子进程定向终止：让路只杀 badging，不误伤图标 dump
    D3    解析期间允许拖入/选择新 APK，最新请求覆盖立即生效

注意：样本识别一律按内容/大小，不依赖 testSample 里的文件名
（GUI 的"执行重命名"会把样本改成 应用名_版本号.apk）。
"""
import io
import math
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

import pytest


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
SAMPLE_DIR = os.path.join(REPO, "testSample")

import numpy as np
from PIL import Image, ImageDraw

import core.aapt as aapt_mod
import core.apk_parser as apk_parser_mod
import core.colors as colors_mod
import core.resources as resources_mod
import core.vector as vector_mod
import ui.main_window as main_window_mod
import ui.workers as workers_mod
from PyQt6 import QtCore, QtGui, QtWidgets


# --------------------------------------------------------------------------
# 测试脚手架
# --------------------------------------------------------------------------
class _Checker:
    """断言式检查器：通过即静默，失败直接抛 AssertionError 交由 pytest 报告。

    保留 C.check / C.skip / C.title 的调用形态，让各检查函数与历史验证
    脚本一一对应，便于对照提交与回归项；但不再自行累积结果与打印汇总。
    """

    @staticmethod
    def check(name, ok, detail=""):
        if not ok:
            raise AssertionError(f"{name} :: {detail}" if detail else name)

    @staticmethod
    def skip(name, detail=""):
        pytest.skip(f"{name}: {detail}" if detail else name)

    @staticmethod
    def title(text):
        """分节标题：pytest 以测试函数名分组，这里仅保留调用点便于阅读。"""


C = _Checker()
MODAL_CALLS = []


def silence_dialogs():
    """把所有模态对话框替换成记录器，避免无人值守时阻塞。"""
    QtWidgets.QMessageBox.information = staticmethod(
        lambda *a, **k: MODAL_CALLS.append(("information", a[2] if len(a) > 2 else "")))
    QtWidgets.QMessageBox.warning = staticmethod(
        lambda *a, **k: MODAL_CALLS.append(("warning", a[2] if len(a) > 2 else "")))
    QtWidgets.QMessageBox.critical = staticmethod(
        lambda *a, **k: MODAL_CALLS.append(("critical", a[2] if len(a) > 2 else "")))
    QtWidgets.QMessageBox.about = staticmethod(lambda *a, **k: None)
    QtWidgets.QMessageBox.question = staticmethod(
        lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes)


def flat(d):
    """把路径数据展开成一维点列（跨子路径按顺序拼接），用于等价性对照。"""
    subs = vector_mod._flatten_subpaths(vector_mod._parse_path_commands(vector_mod._tokenize_path_data(d)), 1.0)
    return [p for sub in subs for p in sub]


_TOKEN_RE = re.compile(r"[MmLlCcSsQqTtZz]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_ARITY = {"M": 2, "L": 2, "C": 6, "S": 4, "Q": 4, "T": 2, "Z": 0}


def abs_to_rel(d):
    """把绝对路径机械改写成等价相对路径（仅 M/L/C/S/Q/T/Z），用于对照测试。"""
    toks = _TOKEN_RE.findall(d)
    out, i, cur, cmd = [], 0, [0.0, 0.0], None
    while i < len(toks):
        if toks[i] in _ARITY:
            cmd = toks[i]
            i += 1
            if cmd == "Z":
                out.append("Z ")
                continue
        n = _ARITY[cmd]
        args = [float(t) for t in toks[i:i + n]]
        i += n
        # 相对坐标一律以「本段起点」为基准（不是上一对控制点）
        sx, sy = cur[0], cur[1]
        rel = []
        for k in range(0, n, 2):
            rel.append(args[k] - sx)
            rel.append(args[k + 1] - sy)
        cur = [args[n - 2], args[n - 1]]
        out.append(cmd.lower() + " " + " ".join("%.6f" % v for v in rel) + " ")
    return "".join(out)


def max_dev(pa, pr):
    if len(pa) != len(pr):
        return float("inf")
    return max(max(abs(x[0] - y[0]), abs(x[1] - y[1])) for x, y in zip(pa, pr))


def reference_fill_mask(W, H, subpaths, fill_rule="nonzero"):
    """按行广播的旧实现，作为分块版本的结果基准。"""
    arr = np.zeros((H, W), dtype=np.uint8)
    edges = vector_mod._collect_edges(subpaths)
    if not edges:
        return arr
    x1 = np.array([e[0] for e in edges])
    y1 = np.array([e[1] for e in edges])
    x2 = np.array([e[2] for e in edges])
    y2 = np.array([e[3] for e in edges])
    y_lo = max(0, int(math.floor(min(y1.min(), y2.min()))))
    y_hi = min(H, int(math.ceil(max(y1.max(), y2.max()))))
    if y_lo >= y_hi:
        return arr
    ys = np.arange(y_lo, y_hi) + 0.5
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
            starts, ends = row[0::2], row[1::2]
        else:
            wrow = wnd[keep]
            order = np.argsort(row, kind="stable")
            row = row[order]
            acc = np.cumsum(wrow[order])
            inside = acc != 0
            if not inside.any():
                continue
            trans = np.diff(np.concatenate(([0], inside.astype(np.int8), [0])))
            starts = row[np.flatnonzero(trans == 1)]
            ends = row[np.flatnonzero(trans == -1)]
        for a, b in zip(starts, ends):
            ia = max(0, int(math.ceil(a - 0.5)))
            ib = min(W, int(math.floor(b + 0.5)))
            if ia < ib:
                arr[y, ia:ib] = 255
    return arr


def circle(cx, cy, r, n=64, ccw=False):
    pts = []
    for i in range(n + 1):
        a = 2 * math.pi * i / n
        pts.append((cx + r * math.cos(-a if ccw else a), cy + r * math.sin(-a if ccw else a)))
    return pts


def sample_apks(limit=None):
    if not os.path.isdir(SAMPLE_DIR):
        return []
    apks = sorted(
        os.path.join(SAMPLE_DIR, f) for f in os.listdir(SAMPLE_DIR) if f.lower().endswith(".apk"))
    return apks[:limit] if limit else apks


def pick_apk(apks, largest=False):
    """按体积挑样本：不依赖文件名（用户可能已经用重命名功能改过名）。"""
    return (max if largest else min)(apks, key=os.path.getsize)


def icon_xml_of(apk):
    """取 badging 里密度最高的 xml 图标路径。"""
    badging = aapt_mod.run_aapt2_dump_badging(apk)
    icons = re.findall(r"application-icon-(\d+):'([^']+)'", badging)
    xmls = [p for _, p in sorted(icons, key=lambda x: int(x[0]), reverse=True)
            if p.lower().endswith(".xml")]
    return xmls[0] if xmls else None


def consume_events(app, seconds=0.02):
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.005)


def wait_for(app, predicate, timeout=60.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.03)
    return False


# --------------------------------------------------------------------------
# 各修复项验证
# --------------------------------------------------------------------------
def check_env():
    C.title("0. 环境")
    try:
        aapt2_path = aapt_mod.find_aapt2()
        C.check("aapt2 可用", True, aapt2_path)
    except Exception as e:
        # 没有 aapt2 时不要在这里抛异常中断整套用例；后续依赖 aapt2 的
        # 真实样本用例会自行跳过。
        C.skip("aapt2 可用", str(e))
    C.check("numpy 可用（矢量栅格化向量化路径）", vector_mod.np is not None, "numpy %s" % (np.__version__,))
    C.check("PyQt6 / Pillow 版本", True,
            "PyQt6 %s · Qt %s · Pillow %s" % (
                QtCore.PYQT_VERSION_STR, QtCore.QT_VERSION_STR, Image.__version__))
    apks = sample_apks()
    if apks:
        C.check("样本 APK", True, "%d 个（%s）" % (len(apks), os.path.basename(SAMPLE_DIR)))
    else:
        # testSample/ 被 .gitignore 排除，CI 与精简环境中没有样本；
        # --quick 的全部用例都应能在无样本时通过。
        C.skip("样本 APK", "testSample 不存在或为空（CI/精简环境）")


def check_p0_1():
    C.title("P0-1 fillType 枚举（evenOdd）")
    C.check("_attr_enum 归一化", [vector_mod._attr_enum(v) for v in ("1", "0x00000001", "evenodd", None)] ==
            ["1", "1", "evenodd", ""],
            "_attr_enum('0x00000001')='%s'" % vector_mod._attr_enum("0x00000001"))

    def rule_of(raw):
        return "evenodd" if vector_mod._attr_enum(raw) in ("1", "evenodd") else "nonzero"

    C.check("fillType=1 → evenodd", rule_of("1") == "evenodd")
    C.check("fillType=0x00000001 → evenodd", rule_of("0x00000001") == "evenodd")
    C.check("fillType=0 → nonzero", rule_of("0") == "nonzero")
    C.check("fillType 缺省 → nonzero", rule_of(None) == "nonzero")

    # 语义：两个同向同心子路径，evenOdd 应保留中间的洞
    subs = [circle(64, 64, 50), circle(64, 64, 20)]
    nz = int(vector_mod._build_fill_mask(128, 128, subs, "nonzero").histogram()[1:][0]) if False else \
        int(sum(vector_mod._build_fill_mask(128, 128, subs, "nonzero").histogram()[1:]))
    eo = int(sum(vector_mod._build_fill_mask(128, 128, subs, "evenodd").histogram()[1:]))
    C.check("同向圆环 evenOdd 面积 < nonzero", eo < nz, "evenOdd=%d px, nonzero=%d px" % (eo, nz))

    # 解析链路：aapt2 xmltree 文本 → _parse_vector_elements → fillType 原始值
    fake = ('E: vector (line=2)\n'
            '  E: path (line=3)\n'
            '    A: http://schemas.android.com/apk/res/android:pathData(0x01010001)="M0,0 L1,1 Z"\n'
            '    A: http://schemas.android.com/apk/res/android:fillType(0x0101019c)=1\n')
    attrs = vector_mod._parse_vector_elements(fake)[1]["attrs"]
    C.check("xmltree 解析 fillType 原始值", attrs.get("fillType") == "1",
            "fillType=%r → %s" % (attrs.get("fillType"), rule_of(attrs.get("fillType"))))

    apks = sample_apks()
    if not apks:
        return
    # 按内容找带 fillType=1 的真实 XML：先看原始字节快速筛选，再交给 aapt2
    target = pick_apk(apks, largest=True)
    hit = None
    dumps = 0
    with zipfile.ZipFile(target) as zf:
        for name in zf.namelist():
            if dumps >= 3 or not name.lower().endswith(".xml"):
                continue
            try:
                raw = zf.open(name).read()
            except Exception:
                continue
            if raw[:4] != b"\x03\x00\x08\x00" or b"fillType" not in raw:
                continue
            dumps += 1
            out = aapt_mod.run_aapt2_dump_xmltree(target, name)
            if re.search(r"fillType\(0x[0-9a-fA-F]+\)=1", out):
                hit = name
                break
    if hit is None:
        # 当前 testSample 可能没有含 fillType=1 的 XML；这是样本缺口，
        # 不应让构建管线误判为代码回归。
        C.skip("真实 APK 中 fillType=1 被识别为 evenOdd",
               "%s 中未找到含 fillType=1 的 XML" % os.path.basename(target)[:30])
    else:
        C.check("真实 APK 中 fillType=1 被识别为 evenOdd", True,
                "%s :: %s" % (os.path.basename(target)[:30], hit))


def check_p0_2():
    C.title("P0-2 相对 s/t 的平滑控制点镜像")
    cases = [
        ("C→S 绝对/相对等价", "M0,0 C10,0 10,10 0,10 S-10,30 0,30", "m0,0 c10,0 10,10 0,10 s-10,20 0,20"),
        ("Q→T 绝对/相对等价", "M0,0 Q10,0 10,10 T20,0", "m0,0 q10,0 10,10 t10,-10"),
        ("相对 c + 绝对 S 混合", "M0,0 C10,0 10,10 0,10 S-10,30 0,30", "M0,0 c10,0 10,10 0,10 S-10,30 0,30"),
        ("连续两段相对 s", "M0,0 C10,0 10,10 0,10 S-10,30 0,30 S-10,50 0,50",
         "m0,0 c10,0 10,10 0,10 s-10,20 0,20 s-10,20 0,20"),
    ]
    for label, a, r in cases:
        dev = max_dev(flat(a), flat(r))
        C.check(label, dev < 1e-9, "最大偏差=%.12f" % dev)

    # 随机路径：机械改写为相对写法后必须完全等价
    random.seed(20240607)
    worst = 0.0
    for _ in range(30):
        parts = ["M%.3f,%.3f" % (random.uniform(0, 100), random.uniform(0, 100))]
        for _ in range(random.randint(1, 4)):
            kind = random.choice("CCSSTTQQ")
            args = [random.uniform(-40, 40) for _ in range(_ARITY[kind])]
            parts.append(kind + " ".join("%.3f" % v for v in args))
        d = " ".join(parts)
        worst = max(worst, max_dev(flat(d), flat(abs_to_rel(d))))
    C.check("30 组随机路径 绝对/相对 完全等价", worst < 1e-9, "最大偏差=%.12f" % worst)


def check_p0_3():
    C.title("P0-3 strokeLineCap 枚举")
    tbl = {raw: vector_mod._VECTOR_CAPS.get(vector_mod._attr_enum(raw), 0)
           for raw in ("butt", "round", "square", "0", "1", "2", "0x00000001")}
    C.check("十进制 1 → round(1)", tbl["1"] == 1)
    C.check("十进制 2 → square(2)", tbl["2"] == 2)
    C.check("十进制 0/butt → 0", tbl["0"] == 0 and tbl["butt"] == 0)
    C.check("名字与 0x 写法仍兼容", tbl["round"] == 1 and tbl["0x00000001"] == 1)
    C.check("未知值回退 butt", vector_mod._VECTOR_CAPS.get(vector_mod._attr_enum("9"), 0) == 0, "%r" % tbl)

    apks = sample_apks(3)
    for apk in apks:
        try:
            xml_path = icon_xml_of(apk)
            if not xml_path:
                continue
            out = aapt_mod.run_aapt2_dump_xmltree(apk, xml_path)
        except Exception:
            continue
        caps = set()
        for el in vector_mod._parse_vector_elements(out):
            v = el["attrs"].get("strokeLineCap")
            if v is not None:
                caps.add((v, vector_mod._VECTOR_CAPS.get(vector_mod._attr_enum(v), 0)))
        if caps:
            C.check("真实 XML 中的 strokeLineCap 映射", all(c != 0 for _, c in caps if _ != "0"),
                    "%s → %s" % (os.path.basename(apk), sorted(caps)))
            return


def check_p1_4(app):
    C.title("P1-4 slot 内异常不再终止进程")
    C.check("install_excepthook 存在且可安装", callable(getattr(main_window_mod, "install_excepthook", None)))
    old_hook = sys.excepthook
    old_thread_hook = threading.excepthook
    main_window_mod.install_excepthook()
    C.check("安装后 sys.excepthook 被替换", sys.excepthook is not old_hook)
    C.check("安装后 threading.excepthook 被替换", threading.excepthook is not old_thread_hook)
    sys.excepthook = old_hook
    threading.excepthook = old_thread_hook

    apks = sample_apks(1)
    if not apks:
        return
    win = main_window_mod.MainWindow()
    win.apk_path_edit.setText(apks[0])
    import ui.main_window as ui_main_mod
    orig = ui_main_mod.parse_aapt2_output
    ui_main_mod.parse_aapt2_output = lambda t: (_ for _ in ()).throw(RuntimeError("verification-injected"))
    try:
        win.process_apk(apks[0])
        finished = wait_for(app, lambda: not win._busy, timeout=20)
        C.check("解析回调抛异常后进程存活", True, "（若能执行到此行即未 qFatal 退出）")
        C.check("异常后 _busy 回到 False", finished and not win._busy, "_busy=%s" % win._busy)
        C.check("界面控件恢复可用", win.btn_browse.isEnabled() and win.apk_path_edit.isEnabled())
        C.check("异常已提示用户", any(k == "critical" for k, _ in MODAL_CALLS),
                "critical 弹窗 %d 次" % sum(1 for k, _ in MODAL_CALLS if k == "critical"))
    finally:
        ui_main_mod.parse_aapt2_output = orig
        win.close()
    # 正常路径不受影响
    win2 = main_window_mod.MainWindow()
    win2.apk_path_edit.setText(apks[0])
    win2.process_apk(apks[0])
    wait_for(app, lambda: not win2._busy, timeout=30)
    C.check("正常解析仍工作", bool(win2.le_app_name.text()), "app_name=%r" % win2.le_app_name.text())
    win2.close()


def check_p1_5(app):
    C.title("P1-5 aapt2 超时 / 可强制结束 / 不再 terminate")
    t0 = time.time()
    timed_out = False
    try:
        aapt_mod._run_aapt2([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1.0)
    except aapt_mod.Aapt2Error:
        timed_out = True
    el = time.time() - t0
    C.check("超时抛 Aapt2Error 且及时返回", timed_out and el < 5, "耗时=%.2fs" % el)
    C.check("超时后进程登记表已清空", len(aapt_mod._running_procs) == 0)

    import threading

    def kill_once_registered():
        # 不能固定 sleep 一段时间再杀：Popen 返回耗时实测在 0.002s~1.0s 之间波动，
        # 固定延迟会赶在子进程登记进 _running_procs 之前执行，什么也杀不到，
        # 于是这里要等满 30s 超时（表现为本用例随机 FAIL）。改为轮询登记表。
        deadline = time.time() + 10
        while time.time() < deadline and not aapt_mod._running_procs:
            time.sleep(0.01)
        aapt_mod.kill_running_aapt2()

    threading.Thread(target=kill_once_registered, daemon=True).start()
    t0 = time.time()
    killed = False
    try:
        rc, out, err = aapt_mod._run_aapt2([sys.executable, "-c", "import time; time.sleep(30)"], timeout=30)
        killed = True
    except aapt_mod.Aapt2Error:
        killed = True
    el = time.time() - t0
    C.check("kill_running_aapt2 能中断运行中的子进程", killed and el < 5, "耗时=%.2fs" % el)

    # D2：定向终止——新一轮解析让路只应结束 badging，不误杀图标线程的
    # resources/xmltree（旧实现无差别 kill，图标提取会被误判失败）。
    def _wait_registered(tag, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            with aapt_mod._running_procs_lock:
                if any(t == tag for t in aapt_mod._running_procs.values()):
                    return True
            time.sleep(0.01)
        return False

    icon_proc = threading.Thread(
        target=lambda: aapt_mod._run_aapt2(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30, tag="xmltree"),
        daemon=True)
    icon_proc.start()
    C.check("图标线程子进程按标签登记", _wait_registered("xmltree"))
    aapt_mod.kill_running_aapt2(tags=("badging",))
    time.sleep(0.2)
    with aapt_mod._running_procs_lock:
        still_running = any(t == "xmltree" for t in aapt_mod._running_procs.values())
    C.check("让路时只杀 badging，不误伤图标 dump", still_running)
    aapt_mod.kill_running_aapt2()
    icon_proc.join(timeout=5)
    C.check("关窗式全量终止仍能结束图标 dump", not icon_proc.is_alive())

    import ast
    has_terminate = False
    for fname in ("main.py", os.path.join("ui", "main_window.py")):
        path = os.path.join(REPO, fname)
        if os.path.isfile(path):
            tree = ast.parse(open(path, encoding="utf-8").read())
            if any(isinstance(node, ast.Attribute) and node.attr == "terminate" for node in ast.walk(tree)):
                has_terminate = True
                break
    C.check("源码中不存在 QThread.terminate 调用", not has_terminate,
            "AST 扫描（注释/docstring 不算）")
    C.check("shutdown_background 存在", hasattr(main_window_mod.MainWindow, "shutdown_background"))

    apks = sample_apks()
    target = pick_apk(apks, largest=True) if apks else None
    if target:
        win = main_window_mod.MainWindow()
        win.apk_path_edit.setText(target)
        win.process_apk(target)
        consume_events(app, 0.2)          # 让 aapt2 真正跑起来
        t0 = time.time()
        win.close()
        el = time.time() - t0
        C.check("解析进行中关窗不再阻塞 10s", el < 3.0, "close() 耗时=%.2fs" % el)
        leftovers = [w for w in (win._apk_worker, win._icon_worker) if w is not None]
        C.check("关闭后线程能收尾", win.shutdown_background(15000),
                "剩余运行中线程=%d" % sum(1 for t in leftovers if t.isRunning()))


def check_p1_6(app):
    C.title("P1-6 / B4 图标提交通道：不阻塞 UI、单线程、最新请求覆盖")

    calls = []
    original_extract = workers_mod.IconWorker._extract

    def slow_extract(self, apk_path, icon_path):
        calls.append(icon_path)
        time.sleep(0.2)
        return QtGui.QImage(4, 4, QtGui.QImage.Format.Format_ARGB32), icon_path.encode()

    workers_mod.IconWorker._extract = slow_extract
    try:
        win = main_window_mod.MainWindow()
        t0 = time.time()
        win._start_icon_worker("a.apk", "res/A.xml")     # 先让它真的开始
        time.sleep(0.05)
        for name in ("B", "C", "D", "E"):
            win._start_icon_worker("a.apk", "res/%s.xml" % name)
            time.sleep(0.05)
        for i in range(20):
            win._start_icon_worker("a.apk", "res/F%d.xml" % i)
        ui_elapsed = time.time() - t0 - 0.25             # 扣掉测试自身的 sleep
        C.check("25 次请求不阻塞 UI 线程", ui_elapsed < 0.2, "UI 侧耗时=%.4fs" % ui_elapsed)
        C.check("只创建一个常驻图标线程", win._icon_worker is not None and win._icon_worker.isRunning(),
                "线程对象=1")
        C.check("中间请求被覆盖跳过（执行次数远小于请求数）", len(calls) <= 3,
                "实际执行 %d 次: %s" % (len(calls), calls))

        ok = wait_for(app, lambda: bool(win._current_icon_bytes), timeout=5)
        C.check("最终显示最新请求的结果", ok and win._current_icon_bytes == b"res/F19.xml",
                "%r" % win._current_icon_bytes)

        win.on_icon_loaded(QtGui.QImage(4, 4, QtGui.QImage.Format.Format_ARGB32),
                           b"stale", win._icon_gen - 1)
        consume_events(app, 0.05)
        C.check("过期代数结果被丢弃", win._current_icon_bytes == b"res/F19.xml")

        # D1：新一轮解析开始（_reset_result_state）后，上一 APK 的在途结果
        # 必须失效——修复前代数不推进，结果会被 on_icon_loaded 接受。
        stale_gen = win._icon_gen
        win._reset_result_state()
        C.check("新一轮解析开始时推进图标代数", win._icon_gen != stale_gen,
                "gen %d -> %d" % (stale_gen, win._icon_gen))
        win.on_icon_loaded(QtGui.QImage(4, 4, QtGui.QImage.Format.Format_ARGB32),
                           b"stale-across-parse", stale_gen)
        consume_events(app, 0.05)
        C.check("旧 APK 的迟到图标结果不再显示",
                win._current_icon_bytes is None and not win.btn_export_icon.isVisibleTo(win),
                "bytes=%r visible=%s" % (win._current_icon_bytes,
                                         win.btn_export_icon.isVisibleTo(win)))
        core = win._icon_worker._core
        with core._lock:
            core_gen = core._gen
        win._icon_worker.cancel()
        C.check("cancel 让在途核心任务立即过期", core.is_stale(core_gen),
                "core gen %d -> %d" % (core_gen, core._gen))

        win.close()
        C.check("关窗后常驻线程退出", win.shutdown_background(5000))
    finally:
        workers_mod.IconWorker._extract = original_extract


def check_p1_7(app):
    C.title("P1-7 process_apk(path) 使用传入路径")
    apks = sample_apks()
    if not apks:
        C.skip("样本 APK 可用", "testSample 为空（CI/精简环境）")
        return
    target = pick_apk(apks)
    win = main_window_mod.MainWindow()
    win.apk_path_edit.clear()             # 输入框故意留空
    win.process_apk(target)
    ok = wait_for(app, lambda: bool(win._current_icon_bytes), timeout=45)
    C.check("输入框为空时仍能提取图标", ok and len(win._current_icon_bytes or b"") > 0,
            "图标字节=%d _icon_gen=%d" % (len(win._current_icon_bytes or b""), win._icon_gen))
    C.check("_current_apk_path 记录传入路径", os.path.normcase(win._current_apk_path()) ==
            os.path.normcase(target))
    win2 = main_window_mod.MainWindow()
    win2.apk_path_edit.setText(target)
    C.check("_apk_path 为空时回退输入框", os.path.normcase(win2._current_apk_path()) ==
            os.path.normcase(target))
    win.close()
    win2.close()


def check_p1_8(app):
    C.title("P1-8 图标失败为非模态提示")
    apks = sample_apks()
    if not apks:
        return
    target = apks[0]
    before = sum(1 for k, _ in MODAL_CALLS if k == "warning")
    win = main_window_mod.MainWindow()
    win.show()
    win.apk_path_edit.setText(target)
    win._apk_path = target
    win._icon_gen += 1
    win._start_icon_worker(target, "res/__not_exist__.xml")
    ok = wait_for(app, lambda: bool(win.lbl_icon_hint.text()), timeout=45)
    after = sum(1 for k, _ in MODAL_CALLS if k == "warning")
    C.check("失败时就地显示提示", ok and "图标提取失败" in win.lbl_icon_hint.text(),
            repr(win.lbl_icon_hint.text()[:40]))
    C.check("失败不再弹模态 warning", after == before, "warning 次数 %d → %d" % (before, after))
    C.check("完整信息在 tooltip 中", bool(win.lbl_icon_hint.toolTip()))
    win.close()


def check_d3_supersede(app):
    C.title("D3 解析期间可继续选择/拖入 APK：最新请求覆盖生效")
    tmpdir = tempfile.mkdtemp(prefix="winapkinfo-supersede-")
    a_path = os.path.join(tmpdir, "a.apk")
    b_path = os.path.join(tmpdir, "b.apk")
    for path in (a_path, b_path):
        with open(path, "wb") as f:
            f.write(b"placeholder")

    saved_badging = workers_mod.run_aapt2_dump_badging

    def fake_badging(path):
        if os.path.normcase(path) == os.path.normcase(a_path):
            time.sleep(1.5)  # 模拟慢解析，保证覆盖发生在解析进行中
            return "package: name='com.slow.a' versionCode='1' versionName='1.0'\n"
        return "package: name='com.fast.b' versionCode='2' versionName='2.0'\n"

    workers_mod.run_aapt2_dump_badging = fake_badging
    try:
        before_crit = sum(1 for k, _ in MODAL_CALLS if k == "critical")
        win = main_window_mod.MainWindow()
        win.process_apk(a_path)
        C.check("解析进行中仍可编辑路径（拖放依赖控件可用）", win.apk_path_edit.isEnabled())
        C.check("解析进行中仍可点击浏览按钮", win.btn_browse.isEnabled())
        t0 = time.time()
        win.process_apk(b_path)             # 覆盖前序请求
        elapsed = time.time() - t0
        C.check("覆盖请求立即返回（不等待旧解析）", elapsed < 0.2, "耗时=%.4fs" % elapsed)
        ok = wait_for(app, lambda: not win._busy and win.le_pkg.text() == "com.fast.b", timeout=10)
        C.check("界面最终显示最新请求的结果", ok,
                "pkg=%r busy=%s" % (win.le_pkg.text(), win._busy))
        time.sleep(1.8)                     # 等慢请求跑完，确认迟到结果被丢弃
        consume_events(app, 0.05)
        C.check("慢请求的迟到结果不覆盖新结果", win.le_pkg.text() == "com.fast.b",
                "pkg=%r" % win.le_pkg.text())
        after_crit = sum(1 for k, _ in MODAL_CALLS if k == "critical")
        C.check("覆盖过程不弹错误对话框", after_crit == before_crit,
                "critical %d -> %d" % (before_crit, after_crit))
        win.close()
    finally:
        workers_mod.run_aapt2_dump_badging = saved_badging
        shutil.rmtree(tmpdir, ignore_errors=True)


def check_p2_9():
    C.title("P2-9 填充掩码分块：结果一致 + 内存下降")
    random.seed(7)
    bad = 0
    for _ in range(30):
        subs = [[(random.uniform(-20, 300), random.uniform(-20, 300))
                 for _ in range(random.randint(3, 40))] for _ in range(random.choice([2, 3, 5, 9]))]
        W = H = random.choice([64, 128, 300])
        for rule in ("nonzero", "evenodd"):
            got = np.asarray(vector_mod._build_fill_mask(W, H, subs, rule))
            exp = reference_fill_mask(W, H, subs, rule)
            if not np.array_equal(got, exp):
                bad += 1
    C.check("分块结果与旧算法逐像素一致", bad == 0, "30 组随机路径 × 2 规则，差异 %d 组" % bad)

    subs = [[(random.uniform(0, 60), random.uniform(0, 60)) for _ in range(6)] for _ in range(3)]
    py_mask = Image.new("L", (64, 64), 0)
    vector_mod._fill_mask_py(py_mask, subs, "evenodd")
    C.check("纯 Python 回退与 numpy 版一致",
            np.array_equal(np.asarray(py_mask), np.asarray(vector_mod._build_fill_mask(64, 64, subs, "evenodd"))))

    import tracemalloc
    pts = [(float((i * 7919) % 1024), float((i * 104729) % 1024)) for i in range(20000)]
    tracemalloc.start()
    t0 = time.time()
    vector_mod._build_fill_mask(1024, 1024, [pts], "nonzero")
    el = time.time() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    C.check("2 万条边峰值内存 < 150MB（原 491MB）", peak < 150 * 1048576,
            "峰值=%.1f MB 耗时=%.2fs" % (peak / 1048576, el))


def check_p2_10():
    C.title("P2-10 aapt2 查找结果被缓存")
    calls = {"n": 0}
    orig_which = shutil.which

    def counting_which(name):
        calls["n"] += 1
        return orig_which(name)

    saved = shutil.which
    shutil.which = counting_which
    try:
        aapt_mod.find_aapt2.cache_clear()
        try:
            p1 = aapt_mod.find_aapt2()
        except Exception as e:
            C.skip("aapt2 查找结果可缓存", str(e))
            return
        calls_after_first = calls["n"]
        t0 = time.time()
        p2 = aapt_mod.find_aapt2()
        el = time.time() - t0
        # 本地 tools/aapt2.exe 存在时第一次不会走 PATH（calls_after_first=0），
        # 因此断言"第二次调用没有新增搜索"，而不是固定等于 1。
        C.check("第二次查找不再搜索 PATH", calls["n"] == calls_after_first,
                "第一次搜索 %d 次，两次合计 %d 次" % (calls_after_first, calls["n"]))
        C.check("第二次查找极快", el < 0.005, "耗时=%.6fs" % el)
        C.check("两次结果一致", p1 == p2, p1)
    finally:
        shutil.which = saved
    tmp_dir = os.path.join(REPO, "_verify_fake_aapt2_dir")
    os.makedirs(tmp_dir, exist_ok=True)
    try:
        aapt_mod.find_aapt2.cache_clear()
        try:
            found = aapt_mod.find_aapt2()
        except Exception as e:
            C.skip("同名目录不会被误判为可执行文件", str(e))
            return
        C.check("同名目录不会被误判为可执行文件",
                os.path.normcase(found) != os.path.normcase(tmp_dir))
    finally:
        os.rmdir(tmp_dir)


CHILD_CODE = r'''
import os, sys, glob, re, subprocess
sys.path.insert(0, sys.argv[1])
import core.aapt as aapt_mod
spawns = {"n": 0}
_orig = subprocess.Popen
class CountingPopen(_orig):
    def __init__(self, *a, **k):
        spawns["n"] += 1
        super().__init__(*a, **k)
subprocess.Popen = CountingPopen
apk = sys.argv[2]
badging = aapt_mod.run_aapt2_dump_badging(apk)
xmls = [p for _, p in re.findall(r"application-icon-(\d+):'([^']+)'", badging) if p.endswith(".xml")]
aapt_mod.run_aapt2_dump_xmltree(apk, xmls[0])
aapt_mod.run_aapt2_dump_resource(apk)
print("SPAWNS=%d" % spawns["n"])
'''


def _run_child(apk, env_extra=None):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, "-c", CHILD_CODE, REPO, apk],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env)
    match = re.search(r"SPAWNS=(\d+)", proc.stdout or "")
    return int(match.group(1)) if match else -1


def check_p2_11():
    C.title("P2-11 磁盘级 dump 缓存（跨进程复用）")
    real_disk_dir = aapt_mod._aapt2_cache._disk_dir
    C.check("磁盘缓存默认启用", bool(real_disk_dir), str(real_disk_dir))
    if not real_disk_dir:
        return
    apks = sample_apks()
    if not apks:
        return

    # 本用例既要改 APK mtime，也要清空缓存目录：全部在临时目录里做，
    # 绝不动 %LOCALAPPDATA%/WinApkInfo/cache 里的真实用户缓存。
    work = tempfile.mkdtemp(prefix="winapkinfo-p211-")
    work_cache = os.path.join(work, "cache")
    os.makedirs(work_cache, exist_ok=True)
    src = pick_apk(apks)
    apk = os.path.join(work, os.path.basename(src))
    shutil.copy2(src, apk)

    saved_env = os.environ.get("WINAPKINFO_CACHE_DIR")
    saved_cache = aapt_mod._aapt2_cache
    os.environ["WINAPKINFO_CACHE_DIR"] = work_cache
    try:
        # 子进程通过 WINAPKINFO_CACHE_DIR 使用同一个临时缓存；
        # 父进程的全局缓存也临时替换，避免 clear/get 落到真实目录。
        aapt_mod._aapt2_cache = aapt_mod._Aapt2OutputCache(disk_dir=work_cache)

        cold = _run_child(apk)
        warm = _run_child(apk)
        C.check("冷磁盘：需要启动 aapt2 子进程", cold > 0, "子进程=%d" % cold)
        C.check("温磁盘：全新进程也不再启动子进程", warm == 0, "子进程=%d" % warm)

        st = os.stat(apk)
        try:
            # 用 ns 精度改/还原 mtime：缓存键是 st_mtime_ns，浮点秒会丢精度
            os.utime(apk, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
            changed = _run_child(apk)
        finally:
            os.utime(apk, ns=(st.st_atime_ns, st.st_mtime_ns))
        C.check("APK mtime 变化后缓存失效", changed > 0, "子进程=%d" % changed)

        disabled = _run_child(apk, {"WINAPKINFO_NO_DISK_CACHE": "1"})
        C.check("禁用磁盘缓存时子进程数回到冷启动水平", disabled > 0,
                "WINAPKINFO_NO_DISK_CACHE=1 → 子进程=%d" % disabled)
        os.environ["WINAPKINFO_NO_DISK_CACHE"] = "1"
        try:
            C.check("_default_disk_cache_dir 尊重禁用开关", aapt_mod._default_disk_cache_dir() is None)
        finally:
            os.environ.pop("WINAPKINFO_NO_DISK_CACHE", None)

        aapt_mod._aapt2_cache.clear()
        C.check("内存层清空后仍能命中磁盘（mtime 已精确还原）",
                aapt_mod._aapt2_cache.get(aapt_mod._aapt2_cache_key(apk, "badging")) is not None)
        key = aapt_mod._aapt2_cache_key(apk, "badging")
        C.check("缓存键包含文件大小、schema 版本与 aapt2 标识",
                len(key) == 7 and key[5] >= 1 and isinstance(key[6], tuple),
                "键字段=%d" % len(key))
    finally:
        aapt_mod._aapt2_cache = saved_cache
        if saved_env is None:
            os.environ.pop("WINAPKINFO_CACHE_DIR", None)
        else:
            os.environ["WINAPKINFO_CACHE_DIR"] = saved_env
        shutil.rmtree(work, ignore_errors=True)


def check_p2_12():
    C.title("P2-12 回归守护：RGBA 缩放不渗透明背景色（复核为误报）")
    # 2x2 -> 1x1：不透明红 + 白色全透明像素
    im = Image.new("RGBA", (2, 2))
    for xy, c in (((0, 0), (255, 0, 0, 255)), ((1, 0), (255, 255, 255, 0)),
                  ((0, 1), (255, 0, 0, 255)), ((1, 1), (255, 255, 255, 0))):
        im.putpixel(xy, c)
    px = im.resize((1, 1), Image.LANCZOS).getpixel((0, 0))
    C.check("Pillow resize 已内置预乘（无白色渗透）", px[1] < 16 and px[2] < 16,
            "2x2→1x1 = %s（未预乘会是 (255,128,128,128)）" % (px,))

    src = Image.new("RGBA", (128, 128), (255, 255, 255, 0))
    ImageDraw.Draw(src).ellipse([16, 16, 112, 112], fill=(255, 0, 0, 255))
    arr = np.asarray(src.resize((32, 32), Image.LANCZOS), dtype=int)
    C.check("透明白底缩放后边缘无白边", int(arr[:, :, 1].max()) == 0,
            "G 通道最大值=%d" % int(arr[:, :, 1].max()))


A1_CHILD = r'''
import os, sys
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, sys.argv[1])
from ui.main_window import install_excepthook
from PyQt6 import QtCore, QtWidgets
app = QtWidgets.QApplication(sys.argv[:1])
install_excepthook()
class Boom(QtCore.QThread):
    def run(self):
        raise RuntimeError("boom-in-thread")
_keep = Boom(); _keep.start()
QtCore.QTimer.singleShot(1200, app.quit)
app.exec()
print("SURVIVED")
'''


def check_a1(app):
    C.title("A1 异常钩子线程安全（不跨线程操作控件）")
    codes = []
    for _ in range(3):
        p = subprocess.run([sys.executable, "-c", A1_CHILD, REPO],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        codes.append((p.returncode, "SURVIVED" in (p.stdout or "")))
    surv = sum(1 for _, ok in codes if ok)
    C.check("子线程未捕获异常时进程存活", surv == len(codes),
            "存活 %d/%d（修复前 1/6，实测退出码 %s）" % (
                surv, len(codes), ["0x%08X" % (c & 0xFFFFFFFF) for c, _ in codes]))

    C.check("_on_gui_thread 在 GUI 线程返回 True", main_window_mod._on_gui_thread())
    off_thread = []
    threading.Thread(target=lambda: off_thread.append(main_window_mod._on_gui_thread())).start()
    time.sleep(0.2)
    C.check("_on_gui_thread 在子线程返回 False", off_thread == [False], "%r" % off_thread)

    shown = []
    original = QtWidgets.QMessageBox.critical
    QtWidgets.QMessageBox.critical = staticmethod(
        lambda *a, **k: shown.append(QtCore.QThread.currentThread() is app.thread()))
    try:
        main_window_mod.install_excepthook()
        import ui.main_window as ui_main_mod
        C.check("钩子已安装且提示器在 GUI 线程创建", ui_main_mod._error_dialog is not None)
        sys.excepthook(RuntimeError, RuntimeError("gui-boom"), None)
        C.check("GUI 线程触发时立即弹窗", shown == [True], "弹窗=%r" % shown)

        shown.clear()
        t = threading.Thread(target=lambda: sys.excepthook(
            RuntimeError, RuntimeError("worker-boom"), None))
        t.start()
        t.join()
        C.check("子线程触发时不跨线程弹窗", shown == [], "当场弹窗=%r" % shown)
        consume_events(app, 0.4)
        C.check("异常经队列投递后在 GUI 线程弹出一次", shown == [True], "弹窗=%r" % shown)

        shown.clear()
        # 纯 threading.Thread 的未捕获异常走 threading.excepthook（不经过
        # sys.excepthook），同样必须只投递、不跨线程弹窗
        t2 = threading.Thread(target=lambda: (_ for _ in ()).throw(RuntimeError("plain-thread-boom")))
        t2.start()
        t2.join()
        C.check("纯线程异常不直接弹窗", shown == [], "当场弹窗=%r" % shown)
        consume_events(app, 0.4)
        C.check("纯线程异常经 threading.excepthook 投递弹窗", shown == [True], "弹窗=%r" % shown)
    finally:
        QtWidgets.QMessageBox.critical = staticmethod(original)
        sys.excepthook = sys.__excepthook__
        threading.excepthook = threading.__excepthook__


def check_b1(app):
    C.title("B1 非 vector 图标层回退到位图")
    fake_bitmap = ('N: android=http://schemas.android.com/apk/res/android (line=1)\n'
                   '  E: bitmap (line=2)\n'
                   '    A: http://schemas.android.com/apk/res/android:src(0x0101019a)=@0x7f080001\n')
    import core.apk_parser as core_apk_parser
    import core.vector as core_vector
    saved_parser = core_apk_parser.run_aapt2_dump_xmltree
    saved_vector = core_vector.run_aapt2_dump_xmltree

    def fake_dump(apk, p, _t=fake_bitmap):
        return _t

    core_apk_parser.run_aapt2_dump_xmltree = fake_dump
    core_vector.run_aapt2_dump_xmltree = fake_dump
    try:
        unwrapped = apk_parser_mod._resolve_xml_wrapper("x.apk", "", "res/x.xml", 0, None)
        raster = vector_mod.rasterize_vector_layer("x.apk", "res/x.xml", 128, "", None)
    finally:
        core_apk_parser.run_aapt2_dump_xmltree = saved_parser
        core_vector.run_aapt2_dump_xmltree = saved_vector
    C.check("<bitmap> 根既不能解引用也不能栅格化（复现失败条件）",
            unwrapped == (None, None, None) and raster is None)

    apks = sample_apks()
    target = None
    for apk in sorted(apks, key=os.path.getsize):
        badging = aapt_mod.run_aapt2_dump_badging(apk)
        icons = sorted(re.findall(r"application-icon-(\d+):'([^']+)'", badging),
                       key=lambda x: -int(x[0]))
        xml = next((p for _, p in icons if p.lower().endswith(".xml")), None)
        if not xml:
            continue
        full = aapt_mod.run_aapt2_dump_resource(apk)
        idx = resources_mod.ResourceIndex(full)
        out = aapt_mod.run_aapt2_dump_xmltree(apk, xml)
        fg = apk_parser_mod.find_adaptive_layer_addr(out, "foreground")
        bg = apk_parser_mod.find_adaptive_layer_addr(out, "background")
        if not (fg and bg):
            continue
        fk, _, _ = apk_parser_mod.resolve_icon_layer(apk, full, fg, index=idx)
        bk, _, _ = apk_parser_mod.resolve_icon_layer(apk, full, bg, index=idx)
        if "vector" in (fk, bk) and apk_parser_mod.find_mipmap_fallback(full, xml, idx):
            target = apk
            break
    if not target:
        C.skip("找到含 vector 层且有位图回退的样本", "样本不足，跳过端到端验证")
        return

    def extract(force_fail):
        win = main_window_mod.MainWindow()
        win.apk_path_edit.setText(target)
        import ui.workers as ui_workers
        import core.apk_parser as core_apk_parser
        import core.vector as core_vector

        saved_workers_raster = ui_workers.rasterize_vector_layer
        saved_parser_raster = core_apk_parser.rasterize_vector_layer
        saved_vector_raster = core_vector.rasterize_vector_layer
        if force_fail:
            def fail_fn(*a, **k):
                return None
            ui_workers.rasterize_vector_layer = fail_fn
            core_apk_parser.rasterize_vector_layer = fail_fn
            core_vector.rasterize_vector_layer = fail_fn
        try:
            win.process_apk(target)
            wait_for(app, lambda: bool(win._current_icon_bytes) or
                     win.lbl_icon_hint.text() != "", timeout=60)
            return win._current_icon_bytes or b"", win.lbl_icon_hint.text()
        finally:
            ui_workers.rasterize_vector_layer = saved_workers_raster
            core_apk_parser.rasterize_vector_layer = saved_parser_raster
            core_vector.rasterize_vector_layer = saved_vector_raster
            win.close()

    normal, _ = extract(False)
    fallback, hint = extract(True)
    C.check("正常路径不受影响", bool(normal), "%d 字节" % len(normal))
    C.check("栅格化失败时改用位图回退（不再直接判失败）",
            bool(fallback) and not hint, "%d 字节（原为失败）" % len(fallback))


def check_b2(full_mode):
    C.title("B2 缓存字节上限")
    tmp = os.path.join(REPO, "_verify_cache_tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        c = aapt_mod._Aapt2OutputCache(capacity=4, disk_dir=tmp, disk_limit=3,
                                disk_max_bytes=500, disk_max_entry=100)
        for i in range(12):
            c.put(("key", i), "x" * 60)
        files = os.listdir(tmp)
        total = sum(os.path.getsize(os.path.join(tmp, f)) for f in files)
        C.check("条目数上限生效", len(files) <= 3, "%d 条" % len(files))
        C.check("总量上限生效", total <= 500, "%d 字节" % total)
        c.put(("big",), "y" * 500)
        C.check("超过单条上限的输出不落盘",
                len(os.listdir(tmp)) == len(files) and c.get(("big",)) is not None,
                "仍在内存层可命中")

        mem = aapt_mod._Aapt2OutputCache(capacity=10, disk_dir=None, mem_max_bytes=100)
        mem.put(("m1",), "x" * 60)
        mem.put(("m2",), "x" * 60)
        C.check("内存层字节上限生效",
                len(mem._cache) == 1 and mem.get(("m1",)) is None and mem.get(("m2",)) == "x" * 60,
                "保留 %d 条" % len(mem._cache))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    C.check("默认上限：单条 8MB / 磁盘 200MB / 内存 64MB",
            aapt_mod._Aapt2OutputCache.DISK_MAX_ENTRY == 8 * 1024 * 1024 and
            aapt_mod._Aapt2OutputCache.DISK_MAX_BYTES == 200 * 1024 * 1024 and
            aapt_mod._Aapt2OutputCache.MEM_MAX_BYTES == 64 * 1024 * 1024)
    if not full_mode:
        return
    disk_dir = aapt_mod._aapt2_cache._disk_dir
    apks = sample_apks()
    if not (disk_dir and apks):
        return
    largest = pick_apk(apks, largest=True)
    aapt_mod.run_aapt2_dump_badging(largest)
    aapt_mod.run_aapt2_dump_resource(largest)      # 该 dump 约 36MB，应只留内存
    files = [(os.path.getsize(os.path.join(disk_dir, f)), f) for f in os.listdir(disk_dir)]
    biggest = max((s for s, _ in files), default=0)
    total = sum(s for s, _ in files)
    C.check("真实样本：单条不超过 8MB", biggest <= aapt_mod._Aapt2OutputCache.DISK_MAX_ENTRY,
            "最大 %.1f MB" % (biggest / 1048576))
    C.check("真实样本：总量不超过 200MB", total <= aapt_mod._Aapt2OutputCache.DISK_MAX_BYTES,
            "合计 %.1f MB / %d 条" % (total / 1048576, len(files)))


def check_b3():
    C.title("B3 SDK 版本表读取失败不再永久缓存")
    import core.resources as core_resources
    saved_res = core_resources.local_resource_path
    saved_cache = core_resources._sdk_versions_cache
    try:
        core_resources._sdk_versions_cache = None
        core_resources.local_resource_path = lambda p: os.path.join("__missing__", p)
        first = dict(core_resources.load_sdk_versions())
        C.check("文件缺失时返回空表且不写缓存",
                first == {} and not core_resources._sdk_versions_cache,
                "cache=%r" % core_resources._sdk_versions_cache)
        core_resources.local_resource_path = saved_res
        second = core_resources.load_sdk_versions()
        C.check("文件恢复后可重新读到（修复前永久为空）", len(second) > 0,
                "%d 条映射" % len(second))
    finally:
        core_resources.local_resource_path = saved_res
        core_resources._sdk_versions_cache = saved_cache


def check_new_fixes():
    C.title("C. 本轮修复的回归守护（无需样本 APK）")

    # --- 渐变 type 枚举（旧实现用 _attr_float，0x 写法被截成 0）---
    C.check("_attr_int 识别十进制/0x 枚举",
            vector_mod._attr_int("1") == 1 and vector_mod._attr_int("0x00000001") == 1 and
            vector_mod._attr_int(None, 9) == 9,
            "_attr_int('0x00000001')=%s" % vector_mod._attr_int("0x00000001"))
    for raw, want in (("1", 1), ("0x00000001", 1), ("2", 2), ("0x00000002", 2)):
        xml = ('E: gradient (line=1)\n'
               '  A: http://schemas.android.com/apk/res/android:type(0x0101019c)=%s\n'
               '  E: item (line=2)\n'
               '    A: http://schemas.android.com/apk/res/android:color(0x0101019d)=#ffff0000\n'
               '  E: item (line=3)\n'
               '    A: http://schemas.android.com/apk/res/android:color(0x0101019d)=#ff0000ff\n' % raw)
        g = vector_mod._parse_gradient(xml)
        C.check("gradient type=%-12s -> %d" % (raw, want), bool(g) and g["type"] == want,
                "解析结果 %s（0=linear 1=radial 2=sweep）" % (g and g["type"]))

    # --- Android 合法的 #RGB / #ARGB 简写 ---
    C.check("parse_android_color 支持 #RGB/#ARGB",
            colors_mod.parse_android_color("#f00") == (255, 0, 0, 255) and
            colors_mod.parse_android_color("#8f00") == (255, 0, 0, 0x88) and
            colors_mod.parse_android_color("#ff112233") == (0x11, 0x22, 0x33, 0xff) and
            colors_mod.parse_android_color("#112233") == (0x11, 0x22, 0x33, 255))
    for bad in ("#gggggg", "#12345", "", "#"):
        try:
            colors_mod.parse_android_color(bad)
            raised = False
        except ValueError:
            raised = True
        C.check("非法颜色 %r 抛统一的格式错误" % bad, raised)

    # --- 畸形 pathData 容错 ---
    try:
        vector_mod._tokenize_path_data("M0,0 L1.2.3 4,4")
        vector_mod._flatten_subpaths(vector_mod._parse_path_commands(vector_mod._tokenize_path_data("M0,0 L1.2.3 4,4")), 1.0)
        ok = True
    except Exception as e:
        ok = False
        C.check("畸形 pathData 不再抛异常", False, repr(e))
    if ok:
        C.check("畸形 pathData 不再抛异常", True, "非法数字被跳过")

    # --- strokeLineCap=square ---
    closed = [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 0.0)]
    C.check("闭合子路径不做 square 端点外推",
            vector_mod._extend_square_caps(closed, 2.0) == closed)
    ext = vector_mod._extend_square_caps([(0.0, 0.0), (10.0, 0.0)], 3.0)
    C.check("square 端点沿线段方向外推半个线宽",
            ext[0] == (-3.0, 0.0) and ext[-1] == (13.0, 0.0), "%r" % (ext,))

    # --- 文件名净化 ---
    sanitized = apk_parser_mod.sanitize_apk_name('a/b:c*?"<>|')
    C.check("文件名净化：非法字符被替换",
            not any(ch in sanitized for ch in '\\/:*?"<>|') and sanitized.endswith(".apk"),
            sanitized)
    C.check("文件名净化：结尾点/空格与保留设备名",
            apk_parser_mod.sanitize_apk_name("name... ") == "name.apk" and
            apk_parser_mod.sanitize_apk_name("CON") == "_CON.apk" and
            apk_parser_mod.sanitize_apk_name("  ") == "" and
            apk_parser_mod.sanitize_apk_name("微信_8.0.1") == "微信_8.0.1.apk",
            "%r %r" % (apk_parser_mod.sanitize_apk_name("name... "), apk_parser_mod.sanitize_apk_name("CON")))

    # --- dump 失败必须可区分 ---
    C.check("dump 失败返回 None（不再把错误文本当输出）",
            aapt_mod.run_aapt2_dump_resource("__no_such__.apk") is None and
            aapt_mod.run_aapt2_dump_xmltree("__no_such__.apk", "res/x.xml") is None)
    try:
        aapt_mod._aapt2_cache_key("__no_such__.apk", "badging")
        err = None
    except Exception as e:
        err = e
    C.check("缓存键对缺失文件抛 Aapt2Error（不是裸 OSError）",
            isinstance(err, aapt_mod.Aapt2Error), repr(err))

    # --- 统一导出规格 ---
    src = io.BytesIO()
    Image.new("RGB", (37, 91), (10, 20, 30)).save(src, format="PNG")
    out_im, out = apk_parser_mod.normalize_icon_image(src.getvalue())
    out_size = out_im.size if out_im else None
    C.check("位图图标归一化为 512×512 PNG",
            out_size == (512, 512) and out.startswith(b"\x89PNG"), "%s" % (out_size,))
    C.check("不可解码的字节返回 (None, b'')（由调用方回退原始字节）",
            apk_parser_mod.normalize_icon_image(b"not an image") == (None, b""))

    # --- 子线程只碰 QImage ---
    C.check("图标链路改用 QImage（子线程不再创建 QPixmap）",
            hasattr(workers_mod.IconWorker, "_load_image") and not hasattr(workers_mod.IconWorker, "_load_pixmap"))

    # --- 无 application-icon-* 时的图标兜底 + 架构去重 ---
    fake = ("package: name='a.b' versionCode='1' versionName='1.0'\n"
            "application: label='X' icon='res/mipmap/ic_launcher.xml'\n"
            "native-code: 'arm64-v8a' 'armeabi-v7a'\n"
            "alt-native-code: 'arm64-v8a'\n")
    info = apk_parser_mod.parse_aapt2_output(fake)
    C.check("无 application-icon-* 时回退 application 节点 icon",
            info["icons"].get("0") == "res/mipmap/ic_launcher.xml", "%r" % info["icons"])
    C.check("native-code / alt-native-code 架构去重",
            info["architectures"] == ["arm64-v8a", "armeabi-v7a"],
            "%r" % info["architectures"])

    # --- package 行属性顺序容错（versionCodeMajor 插在中间时不再整行丢失）---
    info_pkg = apk_parser_mod.parse_aapt2_output(
        "package: name='com.a' versionCode='7' versionCodeMajor='0' versionName='2.3.4'\n")
    C.check("package 行含 versionCodeMajor 仍解析出包名/版本",
            info_pkg["package_name"] == "com.a" and
            info_pkg["version_code"] == "7" and
            info_pkg["version_name"] == "2.3.4",
            "%r / %r / %r" % (info_pkg["package_name"], info_pkg["version_code"],
                              info_pkg["version_name"]))

    # --- find_mipmap_fallback 无 index 路径（曾因未导入 entry_span 抛 NameError）---
    fake_res = ("resource 0x7f0e0001 res/mipmap/ic_launcher\n"
                "    (anydpi-v26) (file) res/mipmap-anydpi-v26/ic_launcher.xml type=XML\n"
                "    (xxxhdpi) (file) res/mipmap-xxxhdpi-v4/ic_launcher.png type=PNG\n")
    fb = apk_parser_mod.find_mipmap_fallback(fake_res, "res/mipmap-anydpi-v26/ic_launcher.xml")
    C.check("find_mipmap_fallback 无 index 也能返回最高密度位图",
            fb == "res/mipmap-xxxhdpi-v4/ic_launcher.png", "%r" % fb)


def check_end_to_end(app, limit):
    C.title("E. 端到端：真实样本 APK 解析 + 图标提取")
    apks = sample_apks(limit)
    if not apks:
        C.check("样本 APK", False, "testSample 目录为空")
        return
    ok = 0
    sizes = []
    non_uniform = []
    for apk in apks:
        name = os.path.basename(apk)
        t0 = time.time()
        win = main_window_mod.MainWindow()
        win.apk_path_edit.setText(apk)
        win.process_apk(apk)
        wait_for(app, lambda: bool(win._current_icon_bytes) or
                 win.lbl_icon_hint.text() != "", timeout=90)
        el = time.time() - t0
        data = win._current_icon_bytes or b""
        size = None
        decode_ok = False
        if data:
            try:
                img = Image.open(io.BytesIO(data))
                img.load()
                size = img.size
                decode_ok = min(size) >= 48
                if size != (512, 512):
                    non_uniform.append((name[:30], size))
            except Exception:
                decode_ok = False
        good = bool(data) and decode_ok
        ok += 1 if good else 0
        sizes.append(size)
        C.check("%s" % name[:44], good,
                "app=%r 图标=%d 字节 %s 耗时=%.2fs" % (
                    win.le_app_name.text()[:14], len(data), size or "-", el))
        win.close()
    C.check("全部样本均成功提取图标", ok == len(apks), "%d/%d" % (ok, len(apks)))
    # 位图/矢量/自适应三条链路统一导出 ICON_SIZE²，否则"导出图标"给出的
    # 文件规格会随图标类型变化
    C.check("图标导出规格统一为 512×512", not non_uniform,
            "非 512² 的有 %d 个：%s" % (len(non_uniform), non_uniform[:3]))

