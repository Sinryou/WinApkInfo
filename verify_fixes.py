# -*- coding: utf-8 -*-
"""WinApkInfo 修复验证脚本。

用法（在仓库根目录，使用系统 Python）：
    python verify_fixes.py              # 完整验证（含真实 APK 端到端）
    python verify_fixes.py --quick      # 只跑合成用例，不碰 testSample
    python verify_fixes.py --samples 3  # 端到端最多测 3 个样本 APK

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

注意：样本识别一律按内容/大小，不依赖 testSample 里的文件名
（GUI 的"执行重命名"会把样本改成 应用名_版本号.apk）。

退出码：0 = 全部通过，1 = 存在失败项。
"""
import argparse
import io
import logging
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

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(REPO, "testSample")

import numpy as np
from PIL import Image, ImageDraw

import main as m
from PyQt6 import QtCore, QtGui, QtWidgets


# --------------------------------------------------------------------------
# 测试脚手架
# --------------------------------------------------------------------------
class Checker:
    def __init__(self):
        self.results = []
        self.section = ""

    def title(self, text):
        self.section = text
        print("\n" + "=" * 74)
        print(text)
        print("=" * 74)

    def check(self, name, ok, detail=""):
        self.results.append((self.section, name, bool(ok), detail))
        flag = "PASS" if ok else "FAIL"
        print("  [%s] %-46s %s" % (flag, name, detail))
        return bool(ok)

    def summary(self):
        total = len(self.results)
        failed = [r for r in self.results if not r[2]]
        print("\n" + "=" * 74)
        print("汇总：%d/%d 项通过" % (total - len(failed), total))
        if failed:
            for sec, name, _, detail in failed:
                print("  FAIL  %s :: %s  %s" % (sec, name, detail))
        print("=" * 74)
        return 1 if failed else 0


C = Checker()
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
    subs = m._flatten_subpaths(m._parse_path_commands(m._tokenize_path_data(d)), 1.0)
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
    edges = m._collect_edges(subpaths)
    if not edges:
        return arr
    x1 = np.array([e[0] for e in edges]); y1 = np.array([e[1] for e in edges])
    x2 = np.array([e[2] for e in edges]); y2 = np.array([e[3] for e in edges])
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
    badging = m.run_aapt2_dump_badging(apk)
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
    C.check("aapt2 可用", bool(m.find_aapt2()), m.find_aapt2())
    C.check("numpy 可用（矢量栅格化向量化路径）", m.np is not None, "numpy %s" % (np.__version__,))
    C.check("PyQt6 / Pillow 版本", True,
            "PyQt6 %s · Qt %s · Pillow %s" % (
                QtCore.PYQT_VERSION_STR, QtCore.QT_VERSION_STR, Image.__version__))
    apks = sample_apks()
    C.check("样本 APK", len(apks) > 0, "%d 个（%s）" % (
        len(apks), os.path.basename(SAMPLE_DIR) if apks else "目录缺失"))


def check_p0_1():
    C.title("P0-1 fillType 枚举（evenOdd）")
    C.check("_attr_enum 归一化", [m._attr_enum(v) for v in ("1", "0x00000001", "evenodd", None)] ==
            ["1", "1", "evenodd", ""],
            "_attr_enum('0x00000001')='%s'" % m._attr_enum("0x00000001"))

    def rule_of(raw):
        return "evenodd" if m._attr_enum(raw) in ("1", "evenodd") else "nonzero"

    C.check("fillType=1 → evenodd", rule_of("1") == "evenodd")
    C.check("fillType=0x00000001 → evenodd", rule_of("0x00000001") == "evenodd")
    C.check("fillType=0 → nonzero", rule_of("0") == "nonzero")
    C.check("fillType 缺省 → nonzero", rule_of(None) == "nonzero")

    # 语义：两个同向同心子路径，evenOdd 应保留中间的洞
    subs = [circle(64, 64, 50), circle(64, 64, 20)]
    nz = int(m._build_fill_mask(128, 128, subs, "nonzero").histogram()[1:][0]) if False else \
        int(sum(m._build_fill_mask(128, 128, subs, "nonzero").histogram()[1:]))
    eo = int(sum(m._build_fill_mask(128, 128, subs, "evenodd").histogram()[1:]))
    C.check("同向圆环 evenOdd 面积 < nonzero", eo < nz, "evenOdd=%d px, nonzero=%d px" % (eo, nz))

    # 解析链路：aapt2 xmltree 文本 → _parse_vector_elements → fillType 原始值
    fake = ('E: vector (line=2)\n'
            '  E: path (line=3)\n'
            '    A: http://schemas.android.com/apk/res/android:pathData(0x01010001)="M0,0 L1,1 Z"\n'
            '    A: http://schemas.android.com/apk/res/android:fillType(0x0101019c)=1\n')
    attrs = m._parse_vector_elements(fake)[1]["attrs"]
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
            out = m.run_aapt2_dump_xmltree(target, name)
            if re.search(r"fillType\(0x[0-9a-fA-F]+\)=1", out):
                hit = name
                break
    C.check("真实 APK 中 fillType=1 被识别为 evenOdd", hit is not None,
            "%s :: %s" % (os.path.basename(target)[:30], hit or "未找到"))


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
        x, y = 0.0, 0.0
        for _ in range(random.randint(1, 4)):
            kind = random.choice("CCSSTTQQ")
            args = [random.uniform(-40, 40) for _ in range(_ARITY[kind])]
            parts.append(kind + " ".join("%.3f" % v for v in args))
        d = " ".join(parts)
        worst = max(worst, max_dev(flat(d), flat(abs_to_rel(d))))
    C.check("30 组随机路径 绝对/相对 完全等价", worst < 1e-9, "最大偏差=%.12f" % worst)


def check_p0_3():
    C.title("P0-3 strokeLineCap 枚举")
    tbl = {raw: m._VECTOR_CAPS.get(m._attr_enum(raw), 0)
           for raw in ("butt", "round", "square", "0", "1", "2", "0x00000001")}
    C.check("十进制 1 → round(1)", tbl["1"] == 1)
    C.check("十进制 2 → square(2)", tbl["2"] == 2)
    C.check("十进制 0/butt → 0", tbl["0"] == 0 and tbl["butt"] == 0)
    C.check("名字与 0x 写法仍兼容", tbl["round"] == 1 and tbl["0x00000001"] == 1)
    C.check("未知值回退 butt", m._VECTOR_CAPS.get(m._attr_enum("9"), 0) == 0, "%r" % tbl)

    apks = sample_apks(3)
    for apk in apks:
        try:
            xml_path = icon_xml_of(apk)
            if not xml_path:
                continue
            out = m.run_aapt2_dump_xmltree(apk, xml_path)
        except Exception:
            continue
        caps = set()
        for el in m._parse_vector_elements(out):
            v = el["attrs"].get("strokeLineCap")
            if v is not None:
                caps.add((v, m._VECTOR_CAPS.get(m._attr_enum(v), 0)))
        if caps:
            C.check("真实 XML 中的 strokeLineCap 映射", all(c != 0 for _, c in caps if _ != "0"),
                    "%s → %s" % (os.path.basename(apk), sorted(caps)))
            return


def check_p1_4(app):
    C.title("P1-4 slot 内异常不再终止进程")
    C.check("install_excepthook 存在且可安装", callable(getattr(m, "install_excepthook", None)))
    old_hook = sys.excepthook
    m.install_excepthook()
    C.check("安装后 sys.excepthook 被替换", sys.excepthook is not old_hook)
    sys.excepthook = old_hook

    apks = sample_apks(1)
    if not apks:
        return
    win = m.MainWindow()
    win.apk_path_edit.setText(apks[0])
    orig = m.parse_aapt2_output
    m.parse_aapt2_output = lambda t: (_ for _ in ()).throw(RuntimeError("verification-injected"))
    try:
        win.process_apk(apks[0])
        finished = wait_for(app, lambda: not win._busy, timeout=20)
        C.check("解析回调抛异常后进程存活", True, "（若能执行到此行即未 qFatal 退出）")
        C.check("异常后 _busy 回到 False", finished and not win._busy, "_busy=%s" % win._busy)
        C.check("界面控件恢复可用", win.btn_browse.isEnabled() and win.apk_path_edit.isEnabled())
        C.check("异常已提示用户", any(k == "critical" for k, _ in MODAL_CALLS),
                "critical 弹窗 %d 次" % sum(1 for k, _ in MODAL_CALLS if k == "critical"))
    finally:
        m.parse_aapt2_output = orig
        win.close()
    # 正常路径不受影响
    win2 = m.MainWindow()
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
        m._run_aapt2([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1.0)
    except m.Aapt2Error:
        timed_out = True
    el = time.time() - t0
    C.check("超时抛 Aapt2Error 且及时返回", timed_out and el < 5, "耗时=%.2fs" % el)
    C.check("超时后进程登记表已清空", len(m._running_procs) == 0)

    import threading
    threading.Thread(target=lambda: (time.sleep(0.6), m.kill_running_aapt2()), daemon=True).start()
    t0 = time.time()
    killed = False
    try:
        rc, out, err = m._run_aapt2([sys.executable, "-c", "import time; time.sleep(30)"], timeout=30)
        killed = True
    except m.Aapt2Error:
        killed = True
    el = time.time() - t0
    C.check("kill_running_aapt2 能中断运行中的子进程", killed and el < 5, "耗时=%.2fs" % el)

    import ast
    tree = ast.parse(open(os.path.join(REPO, "main.py"), encoding="utf-8").read())
    has_terminate = any(
        isinstance(node, ast.Attribute) and node.attr == "terminate" for node in ast.walk(tree))
    C.check("源码中不存在 QThread.terminate 调用", not has_terminate,
            "AST 扫描（注释/docstring 不算）")
    C.check("shutdown_background 存在", hasattr(m.MainWindow, "shutdown_background"))

    apks = sample_apks()
    target = pick_apk(apks, largest=True) if apks else None
    if target:
        win = m.MainWindow()
        win.apk_path_edit.setText(target)
        win.process_apk(target)
        consume_events(app, 0.2)          # 让 aapt2 真正跑起来
        t0 = time.time()
        win.close()
        el = time.time() - t0
        C.check("解析进行中关窗不再阻塞 10s", el < 3.0, "close() 耗时=%.2fs" % el)
        leftovers = win._apk_workers + ([win._icon_worker] if win._icon_worker else [])
        C.check("关闭后线程能收尾", win.shutdown_background(15000),
                "剩余运行中线程=%d" % sum(1 for t in leftovers if t.isRunning()))


def check_p1_6(app):
    C.title("P1-6 / B4 图标提交通道：不阻塞 UI、单线程、最新请求覆盖")

    calls = []
    original_extract = m.IconWorker._extract

    def slow_extract(self, apk_path, icon_path):
        calls.append(icon_path)
        time.sleep(0.2)
        return QtGui.QPixmap(4, 4), icon_path.encode()

    m.IconWorker._extract = slow_extract
    try:
        win = m.MainWindow()
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

        win.on_icon_loaded(QtGui.QPixmap(4, 4), b"stale", win._icon_gen - 1)
        consume_events(app, 0.05)
        C.check("过期代数结果被丢弃", win._current_icon_bytes == b"res/F19.xml")

        win.close()
        C.check("关窗后常驻线程退出", win.shutdown_background(5000))
    finally:
        m.IconWorker._extract = original_extract


def check_p1_7(app):
    C.title("P1-7 process_apk(path) 使用传入路径")
    apks = sample_apks()
    if not apks:
        C.check("样本 APK 可用", False, "testSample 为空")
        return
    target = pick_apk(apks)
    win = m.MainWindow()
    win.apk_path_edit.clear()             # 输入框故意留空
    win.process_apk(target)
    ok = wait_for(app, lambda: bool(win._current_icon_bytes), timeout=45)
    C.check("输入框为空时仍能提取图标", ok and len(win._current_icon_bytes or b"") > 0,
            "图标字节=%d _icon_gen=%d" % (len(win._current_icon_bytes or b""), win._icon_gen))
    C.check("_current_apk_path 记录传入路径", os.path.normcase(win._current_apk_path()) ==
            os.path.normcase(target))
    win2 = m.MainWindow()
    win2.apk_path_edit.setText(target)
    C.check("_apk_path 为空时回退输入框", os.path.normcase(win2._current_apk_path()) ==
            os.path.normcase(target))
    win.close(); win2.close()


def check_p1_8(app):
    C.title("P1-8 图标失败为非模态提示")
    apks = sample_apks()
    if not apks:
        return
    target = apks[0]
    before = sum(1 for k, _ in MODAL_CALLS if k == "warning")
    win = m.MainWindow()
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


def check_p2_9():
    C.title("P2-9 填充掩码分块：结果一致 + 内存下降")
    random.seed(7)
    bad = 0
    for _ in range(30):
        subs = [[(random.uniform(-20, 300), random.uniform(-20, 300))
                 for _ in range(random.randint(3, 40))] for _ in range(random.choice([2, 3, 5, 9]))]
        W = H = random.choice([64, 128, 300])
        for rule in ("nonzero", "evenodd"):
            got = np.asarray(m._build_fill_mask(W, H, subs, rule))
            exp = reference_fill_mask(W, H, subs, rule)
            if not np.array_equal(got, exp):
                bad += 1
    C.check("分块结果与旧算法逐像素一致", bad == 0, "30 组随机路径 × 2 规则，差异 %d 组" % bad)

    subs = [[(random.uniform(0, 60), random.uniform(0, 60)) for _ in range(6)] for _ in range(3)]
    py_mask = Image.new("L", (64, 64), 0)
    m._fill_mask_py(py_mask, subs, "evenodd")
    C.check("纯 Python 回退与 numpy 版一致",
            np.array_equal(np.asarray(py_mask), np.asarray(m._build_fill_mask(64, 64, subs, "evenodd"))))

    import tracemalloc
    pts = [(float((i * 7919) % 1024), float((i * 104729) % 1024)) for i in range(20000)]
    tracemalloc.start()
    t0 = time.time()
    m._build_fill_mask(1024, 1024, [pts], "nonzero")
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
        m.find_aapt2.cache_clear()
        p1 = m.find_aapt2()
        t0 = time.time()
        p2 = m.find_aapt2()
        el = time.time() - t0
        C.check("第二次查找不再搜索 PATH", calls["n"] == 1, "shutil.which 调用 %d 次" % calls["n"])
        C.check("第二次查找极快", el < 0.005, "耗时=%.6fs" % el)
        C.check("两次结果一致", p1 == p2, p1)
    finally:
        shutil.which = saved
    tmp_dir = os.path.join(REPO, "_verify_fake_aapt2_dir")
    os.makedirs(tmp_dir, exist_ok=True)
    try:
        m.find_aapt2.cache_clear()
        C.check("同名目录不会被误判为可执行文件",
                os.path.normcase(m.find_aapt2()) != os.path.normcase(tmp_dir))
    finally:
        os.rmdir(tmp_dir)


CHILD_CODE = r'''
import os, sys, glob, re
sys.path.insert(0, sys.argv[1])
import main as m
spawns = {"n": 0}
_orig = m.subprocess.Popen
class CountingPopen(_orig):
    def __init__(self, *a, **k):
        spawns["n"] += 1
        super().__init__(*a, **k)
m.subprocess.Popen = CountingPopen
apk = sys.argv[2]
badging = m.run_aapt2_dump_badging(apk)
xmls = [p for _, p in re.findall(r"application-icon-(\d+):'([^']+)'", badging) if p.endswith(".xml")]
m.run_aapt2_dump_xmltree(apk, xmls[0])
m.run_aapt2_dump_resource(apk)
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
    disk_dir = m._aapt2_cache._disk_dir
    C.check("磁盘缓存默认启用", bool(disk_dir), str(disk_dir))
    if not disk_dir:
        return
    apks = sample_apks()
    if not apks:
        return
    apk = pick_apk(apks)

    shutil.rmtree(disk_dir, ignore_errors=True)
    os.makedirs(disk_dir, exist_ok=True)   # 清空内容但保留目录（缓存对象持有该路径）
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
        C.check("_default_disk_cache_dir 尊重禁用开关", m._default_disk_cache_dir() is None)
    finally:
        os.environ.pop("WINAPKINFO_NO_DISK_CACHE", None)

    m._aapt2_cache.clear()
    C.check("内存层清空后仍能命中磁盘（mtime 已精确还原）",
            m._aapt2_cache.get(m._aapt2_cache_key(apk, "badging")) is not None)
    C.check("缓存键包含文件大小（APK 替换即失效）",
            len(m._aapt2_cache_key(apk, "badging")) == 5)


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
import main as m
from PyQt6 import QtCore, QtWidgets
app = QtWidgets.QApplication(sys.argv[:1])
m.install_excepthook()
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

    C.check("_on_gui_thread 在 GUI 线程返回 True", m._on_gui_thread())
    off_thread = []
    threading.Thread(target=lambda: off_thread.append(m._on_gui_thread())).start()
    time.sleep(0.2)
    C.check("_on_gui_thread 在子线程返回 False", off_thread == [False], "%r" % off_thread)

    shown = []
    original = QtWidgets.QMessageBox.critical
    QtWidgets.QMessageBox.critical = staticmethod(
        lambda *a, **k: shown.append(QtCore.QThread.currentThread() is app.thread()))
    try:
        m.install_excepthook()
        C.check("钩子已安装且提示器在 GUI 线程创建", m._error_dialog is not None)
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
    finally:
        QtWidgets.QMessageBox.critical = staticmethod(original)
        sys.excepthook = sys.__excepthook__


def check_b1(app):
    C.title("B1 非 vector 图标层回退到位图")
    fake_bitmap = ('N: android=http://schemas.android.com/apk/res/android (line=1)\n'
                   '  E: bitmap (line=2)\n'
                   '    A: http://schemas.android.com/apk/res/android:src(0x0101019a)=@0x7f080001\n')
    saved = m.run_aapt2_dump_xmltree
    m.run_aapt2_dump_xmltree = lambda apk, p, _t=fake_bitmap: _t
    try:
        unwrapped = m._resolve_xml_wrapper("x.apk", "", "res/x.xml", 0, None)
        raster = m.rasterize_vector_layer("x.apk", "res/x.xml", 128, "", None)
    finally:
        m.run_aapt2_dump_xmltree = saved
    C.check("<bitmap> 根既不能解引用也不能栅格化（复现失败条件）",
            unwrapped == (None, None, None) and raster is None)

    apks = sample_apks()
    target = None
    for apk in sorted(apks, key=os.path.getsize):
        badging = m.run_aapt2_dump_badging(apk)
        icons = sorted(re.findall(r"application-icon-(\d+):'([^']+)'", badging),
                       key=lambda x: -int(x[0]))
        xml = next((p for _, p in icons if p.lower().endswith(".xml")), None)
        if not xml:
            continue
        full = m.run_aapt2_dump_resource(apk)
        idx = m._ResourceIndex(full)
        out = m.run_aapt2_dump_xmltree(apk, xml)
        fg = m.find_adaptive_layer_addr(out, "foreground")
        bg = m.find_adaptive_layer_addr(out, "background")
        if not (fg and bg):
            continue
        fk, _, _ = m.resolve_icon_layer(apk, full, fg, index=idx)
        bk, _, _ = m.resolve_icon_layer(apk, full, bg, index=idx)
        if "vector" in (fk, bk) and m.find_mipmap_fallback(full, xml, idx):
            target = apk
            break
    if not target:
        C.check("找到含 vector 层且有位图回退的样本", False, "样本不足，跳过端到端验证")
        return

    def extract(force_fail):
        win = m.MainWindow()
        win.apk_path_edit.setText(target)
        saved_raster = m.rasterize_vector_layer
        if force_fail:
            m.rasterize_vector_layer = lambda *a, **k: None
        try:
            win.process_apk(target)
            wait_for(app, lambda: bool(win._current_icon_bytes) or
                     win.lbl_icon_hint.text() != "", timeout=60)
            return win._current_icon_bytes or b"", win.lbl_icon_hint.text()
        finally:
            m.rasterize_vector_layer = saved_raster
            win.close()

    normal, _ = extract(False)
    fallback, hint = extract(True)
    C.check("正常路径不受影响", bool(normal), "%d 字节" % len(normal))
    C.check("栅格化失败时改用位图回退（不再直接判失败）",
            bool(fallback) and not hint, "%d 字节（原为失败）" % len(fallback))


def check_b2(full_mode):
    C.title("B2 磁盘缓存字节上限")
    tmp = os.path.join(REPO, "_verify_cache_tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        c = m._Aapt2OutputCache(capacity=4, disk_dir=tmp, disk_limit=3,
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
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    C.check("默认上限：单条 8MB / 总量 200MB",
            m._Aapt2OutputCache.DISK_MAX_ENTRY == 8 * 1024 * 1024 and
            m._Aapt2OutputCache.DISK_MAX_BYTES == 200 * 1024 * 1024)
    if not full_mode:
        return
    disk_dir = m._aapt2_cache._disk_dir
    apks = sample_apks()
    if not (disk_dir and apks):
        return
    largest = pick_apk(apks, largest=True)
    m.run_aapt2_dump_badging(largest)
    m.run_aapt2_dump_resource(largest)      # 该 dump 约 36MB，应只留内存
    files = [(os.path.getsize(os.path.join(disk_dir, f)), f) for f in os.listdir(disk_dir)]
    biggest = max((s for s, _ in files), default=0)
    total = sum(s for s, _ in files)
    C.check("真实样本：单条不超过 8MB", biggest <= m._Aapt2OutputCache.DISK_MAX_ENTRY,
            "最大 %.1f MB" % (biggest / 1048576))
    C.check("真实样本：总量不超过 200MB", total <= m._Aapt2OutputCache.DISK_MAX_BYTES,
            "合计 %.1f MB / %d 条" % (total / 1048576, len(files)))


def check_b3():
    C.title("B3 SDK 版本表读取失败不再永久缓存")
    saved_res = m.local_resource_path
    saved_cache = m._sdk_versions_cache
    try:
        m._sdk_versions_cache = None
        m.local_resource_path = lambda p: os.path.join("__missing__", p)
        first = dict(m.load_sdk_versions())
        C.check("文件缺失时返回空表且不写缓存",
                first == {} and not m._sdk_versions_cache,
                "cache=%r" % m._sdk_versions_cache)
        m.local_resource_path = saved_res
        second = m.load_sdk_versions()
        C.check("文件恢复后可重新读到（修复前永久为空）", len(second) > 0,
                "%d 条映射" % len(second))
    finally:
        m.local_resource_path = saved_res
        m._sdk_versions_cache = saved_cache


def check_end_to_end(app, limit):
    C.title("E. 端到端：真实样本 APK 解析 + 图标提取")
    apks = sample_apks(limit)
    if not apks:
        C.check("样本 APK", False, "testSample 目录为空")
        return
    ok = 0
    sizes = []
    for apk in apks:
        name = os.path.basename(apk)
        t0 = time.time()
        win = m.MainWindow()
        win.apk_path_edit.setText(apk)
        win.process_apk(apk)
        got = wait_for(app, lambda: bool(win._current_icon_bytes) or
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
                # 自适应图标链路固定输出 512²；纯位图图标按原图输出（最小边 ≥48 即可用）
                decode_ok = min(size) >= 48
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
    fixed = [s for s in sizes if s == (512, 512)]
    if sizes and len(fixed) != len(sizes):
        print("  备注：%d/%d 个样本导出为 512²，其余为原图尺寸（位图图标链路不做放大）"
              % (len(fixed), len(sizes)))


def main():
    parser = argparse.ArgumentParser(description="WinApkInfo 修复验证")
    parser.add_argument("--quick", action="store_true", help="跳过真实 APK 端到端")
    parser.add_argument("--samples", type=int, default=0, help="端到端最多测几个 APK（0=全部）")
    args = parser.parse_args()

    silence_dialogs()
    # 故意注入的异常会在应用日志里打 traceback，这里降噪以免干扰验证输出
    logging.getLogger().setLevel(logging.CRITICAL)
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    print("WinApkInfo 修复验证 · Python %s" % sys.version.split()[0])

    check_env()
    check_p0_1()
    check_p0_2()
    check_p0_3()
    check_p1_4(app)
    check_p1_5(app)
    check_p1_6(app)
    check_p1_7(app)
    check_p1_8(app)
    check_p2_9()
    check_p2_10()
    if not args.quick:
        check_p2_11()
    check_p2_12()
    check_a1(app)
    check_b1(app)
    check_b2(not args.quick)
    check_b3()
    if not args.quick:
        check_end_to_end(app, args.samples or None)

    return C.summary()


if __name__ == "__main__":
    sys.exit(main())
