# -*- coding: utf-8 -*-
import os
import sys
import re
import io
import math
import hashlib
import tempfile
import shutil
import subprocess
import json
import logging
import threading
import time
import functools
from pathlib import Path
import zipfile
from PIL import Image, ImageChops, ImageDraw

from version import __version__

try:
    import numpy as np
except ImportError:  # numpy 可选：缺失时栅格化回退纯 Python 实现
    np = None

from PyQt6 import QtCore, QtGui, QtWidgets


# subprocess.CREATE_NO_WINDOW 仅存在于 Windows；macOS/Linux 上访问会在运行时报
# AttributeError。此处按平台解析为固定常量，跨平台安全（非 Windows 传 0 即可）。
if sys.platform == "win32":
    _SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _SUBPROCESS_FLAGS = 0


class Aapt2Error(RuntimeError):
    """aapt2 执行失败（非零退出），message 为解码后的 stderr/stdout 文本。"""


# 单个 aapt2 子进程的最长运行时间（秒）：异常的 APK 不应让工作线程永久阻塞
_AAPT2_TIMEOUT = 60
# 关闭窗口时等待后台线程收尾的时间（毫秒）
_CLOSE_WAIT_MS = 5000
# 图标统一导出尺寸：自适应/矢量链路按此合成，位图链路也缩放到此规格，
# 避免同一个"导出图标"按钮因图标类型不同而导出不同尺寸的文件。
_ICON_SIZE = 512

# Windows 保留设备名不能作为文件名（含带扩展名的形式，如 CON.apk）
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# 正在运行的 aapt2 子进程句柄：关闭窗口时用于强制结束，
# 这样工作线程能自己返回，无需（也不该）使用 QThread.terminate()
_running_procs = set()
_running_procs_lock = threading.Lock()


def _run_aapt2(cmd, timeout=_AAPT2_TIMEOUT):
    """运行 aapt2 子进程，返回 (returncode, stdout, stderr)。

    与 subprocess.run 的区别：
    - 带 timeout：超时先 kill 再抛 Aapt2Error；
    - 运行期间把 Popen 登记到 _running_procs，便于关闭窗口时统一结束。
    """
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=_SUBPROCESS_FLAGS,
        )
    except OSError as e:
        raise Aapt2Error(f"无法启动 aapt2：{e}")

    with _running_procs_lock:
        _running_procs.add(proc)
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            raise Aapt2Error(f"aapt2 执行超时（超过 {timeout}s），已终止子进程")
        return proc.returncode, out, err
    finally:
        with _running_procs_lock:
            _running_procs.discard(proc)


def kill_running_aapt2():
    """强制结束所有仍在运行的 aapt2 子进程（关闭窗口/退出时调用）。"""
    with _running_procs_lock:
        procs = list(_running_procs)
    for p in procs:
        try:
            p.kill()
        except Exception:  # 进程可能已经退出
            pass


def _decode_output(data: bytes) -> str:
    """按严格优先级解码 aapt2 输出：utf-8-sig → gbk，最后宽松兜底。

    utf-8-sig 必须排在 utf-8 前面：`bytes.decode("utf-8")` 不会剥离 BOM
    （会把 U+FEFF 留在字符串开头），utf-8-sig 则同时兼容带/不带 BOM 的
    UTF-8 文本。旧实现用 errors="ignore" 逐个尝试，decode 永不抛异常，
    回退链实际是死代码；严格解码才能让回退真正生效。

    回退链里不再列 cp936：它和 gbk 是同一个编解码器
    （`codecs.lookup("cp936").name == "gbk"`），gbk 失败后它必然也失败。
    """
    for enc in ("utf-8-sig", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class _Aapt2OutputCache:
    """按 (apk 路径, mtime_ns, 文件大小, 子命令, 参数) 缓存 aapt2 dump 输出。

    图标解析链路会对同一 APK 反复执行 dump（每个 XML 层一次 xmltree、
    full_res 缺省时多次 resources），缓存可避免重复起子进程。
    键含 mtime 与大小，APK 被替换后自动失效；有界容量 + 线程锁。

    另有可选的磁盘层：让"重新解析/再次打开同一个 APK"在**新进程**里也
    不必重跑 aapt2（实测 Play 商店包单次 dump xmltree 约 2.5s）。磁盘条目
    的键同样包含 mtime_ns 与文件大小，不会读到过期内容；写入用临时文件 +
    os.replace，保证并发下不会读到半个文件。

    磁盘层有双重上限：单条超过 disk_max_entry 的输出（例如几十 MB 的
    resources dump）只留在内存不落盘，整目录再受 disk_limit 条数与
    disk_max_bytes 总字节约束，超限按 mtime 从最旧的开始删。
    """

    # 单条超过 8MB 的 dump 不落盘（Play 商店包实测单条 resources dump 36MB）
    DISK_MAX_ENTRY = 8 * 1024 * 1024
    # 磁盘缓存总量上限 200MB / 300 条
    DISK_MAX_BYTES = 200 * 1024 * 1024
    DISK_LIMIT = 300

    def __init__(self, capacity=64, disk_dir=None, disk_limit=None,
                 disk_max_bytes=None, disk_max_entry=None):
        self._capacity = capacity
        self._cache = {}
        self._order = []
        self._lock = threading.Lock()
        self._disk_dir = disk_dir
        self._disk_limit = self.DISK_LIMIT if disk_limit is None else disk_limit
        self._disk_max_bytes = self.DISK_MAX_BYTES if disk_max_bytes is None else disk_max_bytes
        self._disk_max_entry = self.DISK_MAX_ENTRY if disk_max_entry is None else disk_max_entry
        self._puts_since_prune = 0
        if self._disk_dir:
            try:
                os.makedirs(self._disk_dir, exist_ok=True)
            except OSError:
                self._disk_dir = None  # 目录不可用时静默退回纯内存缓存

    # ---------------- 内存层 ----------------
    def get(self, key):
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        text = self._disk_get(key)
        if text is not None:
            with self._lock:
                self._remember(key, text)
        return text

    def put(self, key, value):
        with self._lock:
            self._remember(key, value)
        self._disk_put(key, value)

    def clear(self):
        """清空内存层（磁盘层保留，测试与调优用）。"""
        with self._lock:
            self._cache.clear()
            del self._order[:]

    def _remember(self, key, value):
        """写入内存层（调用方需持有 _lock）。"""
        if key not in self._cache:
            self._order.append(key)
        self._cache[key] = value
        while len(self._order) > self._capacity:
            self._cache.pop(self._order.pop(0), None)

    # ---------------- 磁盘层 ----------------
    def _disk_path(self, key):
        name = hashlib.sha1(repr(key).encode("utf-8")).hexdigest()
        return os.path.join(self._disk_dir, name + ".txt")

    def _disk_get(self, key):
        if not self._disk_dir:
            return None
        try:
            with open(self._disk_path(key), "rb") as f:
                return f.read().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    def _disk_put(self, key, value):
        if not self._disk_dir:
            return
        # 先编码成字节：既能拿到真实落盘体积，也避免写文件时再编码一次
        try:
            payload = value.encode("utf-8")
        except UnicodeEncodeError:
            return
        if len(payload) > self._disk_max_entry:
            # 超大 dump（如 30MB+ 的 resources 输出）只留在内存层
            logging.debug("dump 输出 %.1fMB 超过单条上限，不写入磁盘缓存",
                          len(payload) / 1048576)
            return
        path = self._disk_path(key)
        # 临时文件名必须唯一：缓存目录是跨进程共享的（多开本程序时），
        # 固定用 path + ".tmp" 会让并发写互相截断，把半截内容 replace 成正式条目。
        try:
            fd, tmp = tempfile.mkstemp(prefix=".tmp", dir=self._disk_dir)
        except OSError:
            return
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
            os.replace(tmp, path)  # 原子替换，避免并发读到半个文件
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return
        self._prune_disk()

    def _prune_disk(self):
        """条目数或总字节数超限时，按 mtime 删除最旧的文件。

        listdir 很便宜，可以每次做；stat 全目录较贵，因此普通写入只在每
        16 次落盘后做一次完整核算。
        """
        try:
            names = os.listdir(self._disk_dir)
        except OSError:
            return
        self._puts_since_prune += 1
        if len(names) <= self._disk_limit and self._puts_since_prune < 16:
            return
        self._puts_since_prune = 0
        entries = []
        total = 0
        for n in names:
            p = os.path.join(self._disk_dir, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            entries.append((st.st_mtime, p, st.st_size))
            total += st.st_size
        if len(entries) <= self._disk_limit and total <= self._disk_max_bytes:
            return
        entries.sort()  # 最旧的先删
        count = len(entries)
        for _, p, size in entries:
            if count <= self._disk_limit and total <= self._disk_max_bytes:
                break
            try:
                os.remove(p)
            except OSError:
                continue
            count -= 1
            total -= size
        logging.debug("磁盘缓存清理完成：%d 条 / %.1fMB", count, total / 1048576)


def _default_disk_cache_dir():
    """磁盘缓存目录；设置 WINAPKINFO_NO_DISK_CACHE=1 可禁用。"""
    if os.environ.get("WINAPKINFO_NO_DISK_CACHE"):
        return None
    return os.path.join(tempfile.gettempdir(), "winapk_info_cache")


_aapt2_cache = _Aapt2OutputCache(disk_dir=_default_disk_cache_dir())


def _aapt2_cache_key(apk_path: str, kind: str, arg=None):
    """(绝对路径, mtime_ns, 大小, 子命令, 参数) 缓存键。

    os.stat 失败时统一抛 Aapt2Error 而不是裸 OSError：调用方
    （run_aapt2_dump_*）的异常处理与提示都是围绕 Aapt2Error 组织的，
    裸 FileNotFoundError 会绕过 ApkInfoWorker 里更贴切的提示分支。
    """
    try:
        st = os.stat(apk_path)
    except OSError as e:
        raise Aapt2Error(f"无法读取 APK 文件：{apk_path}（{e.strerror or e}）")
    return (os.path.abspath(apk_path), st.st_mtime_ns, st.st_size, kind, arg)


def local_resource_path(relative_path):
    """兼容打包前后路径"""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.argv[0])))
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
    # here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    # sdk_file = here / "android_sdk_versions.json"
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

@functools.lru_cache(maxsize=1)
def find_aapt2() -> str:
    """
    优先在脚本同级目录查找 aapt2 / aapt2.exe；否则使用系统 PATH 中的 aapt2。
    找不到则抛出 FileNotFoundError。

    结果用 lru_cache 缓存：一次图标提取可能发起多次 dump，每次都重新探测
    候选文件并搜索 PATH 属于纯浪费（抛出的异常不会被缓存，装好 aapt2 后
    仍可重新探测）。
    """
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # 支持 PyInstaller
    candidates = [here / "aapt2", here / "aapt2.exe", here / "tools" / "aapt2.exe"]
    for c in candidates:
        # 必须要求是文件：Windows 上 os.X_OK 对已存在的路径恒为真，
        # 同名目录会被误当成可执行文件。
        if c.is_file() and os.access(str(c), os.X_OK):
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

    rc, out, err = _run_aapt2(cmd)
    if rc != 0:
        msg = (_decode_output(err or out)).strip() or f"aapt2 退出码 {rc}"
        raise Aapt2Error(msg)

    text = _decode_output(out)
    _aapt2_cache.put(key, text)
    return text

def run_aapt2_dump_resource(apk_path: str):
    """
    运行 `aapt2 dump resources "<apk>"` 并返回完整 stdout 文本；**失败返回 None**。

    旧实现在失败时把错误文本当成正常 dump 返回，错误与真实输出无法区分：
    上层只能靠"解析不出条目"间接推断失败，日志里也留不下线索。现在失败统一
    返回 None 并记 warning，由调用方（图标链路）决定降级到位图回退。

    注意：这里返回全量输出而不是按地址截取的上下文窗口。旧实现用「±10 行」的
    模糊窗口去匹配 `resource {id} (.*?)resource 0x`，当目标条目恰好是资源表
    最后一条（后面没有下一个 `resource 0x`）或条目密度变体超过 10 行时，
    窗口里取不到终止符/完整内容，会误判为 unknown。全量输出交给
    extract_resource_entry 做精确、无歧义的条目截取。
    """
    try:
        aapt2_path = find_aapt2()
        key = _aapt2_cache_key(apk_path, "resources")
        cached = _aapt2_cache.get(key)
        if cached is not None:
            return cached

        rc, out, err = _run_aapt2([aapt2_path, "dump", "resources", apk_path])
        if rc != 0:
            raise Aapt2Error((_decode_output(err or out)).strip() or f"aapt2 退出码 {rc}")
        text = _decode_output(out)
    except Exception as e:
        logging.warning("aapt2 dump resources 失败（%s）：%s", apk_path, e)
        return None

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

    lines = (full_output or "").splitlines()
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

def run_aapt2_dump_xmltree(apk_path: str, inner_file_path: str):
    """
    运行 `aapt2 dump xmltree "<apk>" --file <inner_file_path>` 并返回 stdout 文本；
    **失败返回 None**（契约同 run_aapt2_dump_resource，见其说明）。
    """
    try:
        aapt2_path = find_aapt2()
        key = _aapt2_cache_key(apk_path, "xmltree", inner_file_path)
        cached = _aapt2_cache.get(key)
        if cached is not None:
            return cached

        cmd = [aapt2_path, "dump", "xmltree", apk_path, "--file", inner_file_path]
        rc, out, err = _run_aapt2(cmd)
        if rc != 0:
            raise Aapt2Error((_decode_output(err or out)).strip() or f"aapt2 退出码 {rc}")
        text = _decode_output(out)
    except Exception as e:
        logging.warning("aapt2 dump xmltree 失败（%s :: %s）：%s", apk_path, inner_file_path, e)
        return None

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
            "type": "ref",         "value": 另一个资源地址（如 "@0x0106003b"）
            "type": "unknown",     "value": None
        }

    "ref" 是 Android 资源别名：`aapt2 dump resources` 对颜色别名输出
    `() @0x0106003b`（RootMyVivo 的 launcher 颜色就全部是这种写法），
    旧实现不识别该行，导致颜色层被判为 unknown、整张图标透明。
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
                continue
        if ref is None:
            m = ref_re.match(line)
            if m:
                ref = m.group(1).lower()

    if bitmaps:
        return {"type": "image", "value": _pick_best_density(bitmaps)}
    if color:
        return {"type": "color", "value": color}
    if xml_files:
        return {"type": "vector", "value": xml_files[0]}
    if ref:
        return {"type": "ref", "value": ref}
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
    kind, value, scale2 = resolve_icon_layer(apk_path, full_res, m.group(1), depth + 1, index)
    if not kind:
        return (None, None, None)
    return (kind, value, scale or scale2)


def resolve_icon_layer(apk_path: str, full_res: str, res_id: str, depth: int = 0, index=None):
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
    以及应用内资源别名（`() @0x7f......`，颜色资源常见的间接层）。
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
    if kind == "ref" and value:
        # 应用内别名：继续跟随（目标可能是颜色/位图/矢量，也可能是框架颜色）
        return resolve_icon_layer(apk_path, full_res, value, depth + 1, index)
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
    a, b = _entry_span(lines, start)
    return _pick_best_density(_collect_bitmap_variants("\n".join(lines[a:b])))

def parse_android_color(color_str: str):
    """
    把 Android 颜色字符串转成 Pillow 可用的 (R, G, B, A)。

    支持 Android 认可的四种写法：#RGB、#ARGB、#RRGGBB、#AARRGGBB。
    旧实现只认 6/8 位，`#f00` 这类合法简写会抛异常导致整层填充被静默跳过；
    非法输入（如 `#gggggg`）抛的也是底层的 ValueError，不是统一的格式错误。
    """
    s = (color_str or "").strip().lstrip('#')
    try:
        if len(s) == 3:      # RGB
            r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, 255)
        if len(s) == 4:      # ARGB
            a, r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, a)
        if len(s) == 6:      # RRGGBB
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), 255)
        if len(s) == 8:      # AARRGGBB
            return (int(s[2:4], 16), int(s[4:6], 16), int(s[6:8], 16), int(s[0:2], 16))
    except ValueError:
        pass
    raise ValueError("不合法的颜色格式: " + str(color_str))

# ---------------- Vector Drawable 栅格化 ----------------

# Android 框架（android 包）颜色资源表：键为 AOSP public-final.xml 中的公开
# color 资源 ID，值为 colors*.xml 的默认 ARGB。用于解析 0x01xxxxxx 引用
# （自适应图标背景/前景常直接引用 @android:color/...）。
#
# system_* 是 Material You 动态色，设备上可被 OverlayManager 按壁纸替换；
# 这里使用 AOSP 默认调色板（Pixel 默认主题）。静态解析拿不到用户主题，
# 取默认值仍能渲染出接近真实图标的颜色，比按"未知"当透明更可用。
_FRAMEWORK_COLOR_MAP = {
    "0x01060000": "#ffaaaaaa",  # darker_gray
    "0x0106000b": "#ffffffff",  # white
    "0x0106000c": "#ff000000",  # black
    "0x0106000d": "#00000000",  # transparent
    "0x0106000e": "#ff000000",  # background_dark
    "0x0106000f": "#ffffffff",  # background_light
    "0x01060012": "#ff33b5e5",  # holo_blue_light
    "0x01060013": "#ff0099cc",  # holo_blue_dark
    "0x01060014": "#ff99cc00",  # holo_green_light
    "0x01060015": "#ff669900",  # holo_green_dark
    "0x01060016": "#ffff4444",  # holo_red_light
    "0x01060017": "#ffcc0000",  # holo_red_dark
    "0x01060018": "#ffffbb33",  # holo_orange_light
    "0x01060019": "#ffff8800",  # holo_orange_dark
    "0x0106001a": "#ffaa66cc",  # holo_purple
    "0x0106001b": "#ff00ddff",  # holo_blue_bright
    "0x0106001c": "#00000000",  # system_notification_accent_color
    "0x0106001d": "#ffffffff",  # system_neutral1_0
    "0x0106001e": "#fffefbff",  # system_neutral1_10
    "0x0106001f": "#fff1f0f7",  # system_neutral1_50
    "0x01060020": "#ffe2e2e9",  # system_neutral1_100
    "0x01060021": "#ffc6c6cd",  # system_neutral1_200
    "0x01060022": "#ffababb1",  # system_neutral1_300
    "0x01060023": "#ff909097",  # system_neutral1_400
    "0x01060024": "#ff76777d",  # system_neutral1_500
    "0x01060025": "#ff5d5e64",  # system_neutral1_600
    "0x01060026": "#ff45464c",  # system_neutral1_700
    "0x01060027": "#ff2f3036",  # system_neutral1_800
    "0x01060028": "#ff1a1b20",  # system_neutral1_900
    "0x01060029": "#ff000000",  # system_neutral1_1000
    "0x0106002a": "#ffffffff",  # system_neutral2_0
    "0x0106002b": "#fffefbff",  # system_neutral2_10
    "0x0106002c": "#fff0f0fa",  # system_neutral2_50
    "0x0106002d": "#ffe1e2ec",  # system_neutral2_100
    "0x0106002e": "#ffc5c6d0",  # system_neutral2_200
    "0x0106002f": "#ffa9abb4",  # system_neutral2_300
    "0x01060030": "#ff8f9099",  # system_neutral2_400
    "0x01060031": "#ff757780",  # system_neutral2_500
    "0x01060032": "#ff5c5e67",  # system_neutral2_600
    "0x01060033": "#ff44464f",  # system_neutral2_700
    "0x01060034": "#ff2e3038",  # system_neutral2_800
    "0x01060035": "#ff191b23",  # system_neutral2_900
    "0x01060036": "#ff000000",  # system_neutral2_1000
    "0x01060037": "#ffffffff",  # system_accent1_0
    "0x01060038": "#fffefbff",  # system_accent1_10
    "0x01060039": "#ffeef0ff",  # system_accent1_50
    "0x0106003a": "#ffd9e2ff",  # system_accent1_100
    "0x0106003b": "#ffb0c6ff",  # system_accent1_200
    "0x0106003c": "#ff94aae4",  # system_accent1_300
    "0x0106003d": "#ff7a90c8",  # system_accent1_400
    "0x0106003e": "#ff6076ac",  # system_accent1_500
    "0x0106003f": "#ff475d92",  # system_accent1_600
    "0x01060040": "#ff2f4578",  # system_accent1_700
    "0x01060041": "#ff152e60",  # system_accent1_800
    "0x01060042": "#ff001945",  # system_accent1_900
    "0x01060043": "#ff000000",  # system_accent1_1000
    "0x01060044": "#ffffffff",  # system_accent2_0
    "0x01060045": "#fffefbff",  # system_accent2_10
    "0x01060046": "#ffeef0ff",  # system_accent2_50
    "0x01060047": "#ffdce2f9",  # system_accent2_100
    "0x01060048": "#ffc0c6dc",  # system_accent2_200
    "0x01060049": "#ffa4abc1",  # system_accent2_300
    "0x0106004a": "#ff8a90a5",  # system_accent2_400
    "0x0106004b": "#ff70778b",  # system_accent2_500
    "0x0106004c": "#ff575e71",  # system_accent2_600
    "0x0106004d": "#ff404659",  # system_accent2_700
    "0x0106004e": "#ff2a3042",  # system_accent2_800
    "0x0106004f": "#ff151b2c",  # system_accent2_900
    "0x01060050": "#ff000000",  # system_accent2_1000
    "0x01060051": "#ffffffff",  # system_accent3_0
    "0x01060052": "#fffffbff",  # system_accent3_10
    "0x01060053": "#ffffebfa",  # system_accent3_50
    "0x01060054": "#fffdd7fa",  # system_accent3_100
    "0x01060055": "#ffe0bbdd",  # system_accent3_200
    "0x01060056": "#ffc3a0c1",  # system_accent3_300
    "0x01060057": "#ffa886a6",  # system_accent3_400
    "0x01060058": "#ff8c6d8c",  # system_accent3_500
    "0x01060059": "#ff725572",  # system_accent3_600
    "0x0106005a": "#ff593d59",  # system_accent3_700
    "0x0106005b": "#ff412742",  # system_accent3_800
    "0x0106005c": "#ff2a122c",  # system_accent3_900
    "0x0106005d": "#ff000000",  # system_accent3_1000
    "0x0106005e": "#ffd9e2ff",  # system_primary_container_light
    "0x0106005f": "#ff2f4578",  # system_on_primary_container_light
    "0x01060060": "#ff475d92",  # system_primary_light
    "0x01060061": "#ffffffff",  # system_on_primary_light
    "0x01060062": "#ffdce2f9",  # system_secondary_container_light
    "0x01060063": "#ff404659",  # system_on_secondary_container_light
    "0x01060064": "#ff575e71",  # system_secondary_light
    "0x01060065": "#ffffffff",  # system_on_secondary_light
    "0x01060066": "#fffdd7fa",  # system_tertiary_container_light
    "0x01060067": "#ff593d59",  # system_on_tertiary_container_light
    "0x01060068": "#ff725572",  # system_tertiary_light
    "0x01060069": "#ffffffff",  # system_on_tertiary_light
    "0x0106006a": "#fffaf8ff",  # system_background_light
    "0x0106006b": "#ff1a1b20",  # system_on_background_light
    "0x0106006c": "#fffaf8ff",  # system_surface_light
    "0x0106006d": "#ff1a1b20",  # system_on_surface_light
    "0x0106006e": "#fff4f3fa",  # system_surface_container_low_light
    "0x0106006f": "#ffffffff",  # system_surface_container_lowest_light
    "0x01060070": "#ffeeedf4",  # system_surface_container_light
    "0x01060071": "#ffe8e7ef",  # system_surface_container_high_light
    "0x01060072": "#ffe2e2e9",  # system_surface_container_highest_light
    "0x01060073": "#fffaf8ff",  # system_surface_bright_light
    "0x01060074": "#ffdad9e0",  # system_surface_dim_light
    "0x01060075": "#ffe1e2ec",  # system_surface_variant_light
    "0x01060076": "#ff44464f",  # system_on_surface_variant_light
    "0x01060077": "#ff757780",  # system_outline_light
    "0x01060078": "#ffba1a1a",  # system_error_light
    "0x01060079": "#ffffffff",  # system_on_error_light
    "0x0106007a": "#ffffdad6",  # system_error_container_light
    "0x0106007b": "#ff93000a",  # system_on_error_container_light
    "0x0106007c": "#ffd9e2ff",  # system_control_activated_light
    "0x0106007d": "#ff44464f",  # system_control_normal_light
    "0x0106007e": "#ff000000",  # system_control_highlight_light
    "0x0106007f": "#ffe2e2e9",  # system_text_primary_inverse_light
    "0x01060080": "#ffc5c6d0",  # system_text_secondary_and_tertiary_inverse_light
    "0x01060081": "#ffe2e2e9",  # system_text_primary_inverse_disable_only_light
    "0x01060082": "#ffe2e2e9",  # system_text_secondary_and_tertiary_inverse_disabled_light
    "0x01060083": "#ffe2e2e9",  # system_text_hint_inverse_light
    "0x01060084": "#ff6076ac",  # system_palette_key_color_primary_light
    "0x01060085": "#ff70778b",  # system_palette_key_color_secondary_light
    "0x01060086": "#ff8c6d8c",  # system_palette_key_color_tertiary_light
    "0x01060087": "#ff76777d",  # system_palette_key_color_neutral_light
    "0x01060088": "#ff757780",  # system_palette_key_color_neutral_variant_light
    "0x01060089": "#ff2f4578",  # system_primary_container_dark
    "0x0106008a": "#ffd9e2ff",  # system_on_primary_container_dark
    "0x0106008b": "#ffb0c6ff",  # system_primary_dark
    "0x0106008c": "#ff152e60",  # system_on_primary_dark
    "0x0106008d": "#ff404659",  # system_secondary_container_dark
    "0x0106008e": "#ffdce2f9",  # system_on_secondary_container_dark
    "0x0106008f": "#ffc0c6dc",  # system_secondary_dark
    "0x01060090": "#ff2a3042",  # system_on_secondary_dark
    "0x01060091": "#ff593d59",  # system_tertiary_container_dark
    "0x01060092": "#fffdd7fa",  # system_on_tertiary_container_dark
    "0x01060093": "#ffe0bbdd",  # system_tertiary_dark
    "0x01060094": "#ff412742",  # system_on_tertiary_dark
    "0x01060095": "#ff121318",  # system_background_dark
    "0x01060096": "#ffe2e2e9",  # system_on_background_dark
    "0x01060097": "#ff121318",  # system_surface_dark
    "0x01060098": "#ffe2e2e9",  # system_on_surface_dark
    "0x01060099": "#ff1a1b20",  # system_surface_container_low_dark
    "0x0106009a": "#ff0c0e13",  # system_surface_container_lowest_dark
    "0x0106009b": "#ff1e1f25",  # system_surface_container_dark
    "0x0106009c": "#ff282a2f",  # system_surface_container_high_dark
    "0x0106009d": "#ff33343a",  # system_surface_container_highest_dark
    "0x0106009e": "#ff38393f",  # system_surface_bright_dark
    "0x0106009f": "#ff121318",  # system_surface_dim_dark
    "0x010600a0": "#ff44464f",  # system_surface_variant_dark
    "0x010600a1": "#ffc5c6d0",  # system_on_surface_variant_dark
    "0x010600a2": "#ff8f9099",  # system_outline_dark
    "0x010600a3": "#ffffb4ab",  # system_error_dark
    "0x010600a4": "#ff690005",  # system_on_error_dark
    "0x010600a5": "#ff93000a",  # system_error_container_dark
    "0x010600a6": "#ffffdad6",  # system_on_error_container_dark
    "0x010600a7": "#ff2f4578",  # system_control_activated_dark
    "0x010600a8": "#ffc5c6d0",  # system_control_normal_dark
    "0x010600a9": "#ffffffff",  # system_control_highlight_dark
    "0x010600aa": "#ff1a1b20",  # system_text_primary_inverse_dark
    "0x010600ab": "#ff44464f",  # system_text_secondary_and_tertiary_inverse_dark
    "0x010600ac": "#ff1a1b20",  # system_text_primary_inverse_disable_only_dark
    "0x010600ad": "#ff1a1b20",  # system_text_secondary_and_tertiary_inverse_disabled_dark
    "0x010600ae": "#ff1a1b20",  # system_text_hint_inverse_dark
    "0x010600af": "#ff6076ac",  # system_palette_key_color_primary_dark
    "0x010600b0": "#ff70778b",  # system_palette_key_color_secondary_dark
    "0x010600b1": "#ff8c6d8c",  # system_palette_key_color_tertiary_dark
    "0x010600b2": "#ff76777d",  # system_palette_key_color_neutral_dark
    "0x010600b3": "#ff757780",  # system_palette_key_color_neutral_variant_dark
    "0x010600b4": "#ffd9e2ff",  # system_primary_fixed
    "0x010600b5": "#ffb0c6ff",  # system_primary_fixed_dim
    "0x010600b6": "#ff001945",  # system_on_primary_fixed
    "0x010600b7": "#ff2f4578",  # system_on_primary_fixed_variant
    "0x010600b8": "#ffdce2f9",  # system_secondary_fixed
    "0x010600b9": "#ffc0c6dc",  # system_secondary_fixed_dim
    "0x010600ba": "#ff151b2c",  # system_on_secondary_fixed
    "0x010600bb": "#ff404659",  # system_on_secondary_fixed_variant
    "0x010600bc": "#fffdd7fa",  # system_tertiary_fixed
    "0x010600bd": "#ffe0bbdd",  # system_tertiary_fixed_dim
    "0x010600be": "#ff2a122c",  # system_on_tertiary_fixed
    "0x010600bf": "#ff593d59",  # system_on_tertiary_fixed_variant
    "0x010600c0": "#ffc5c6d0",  # system_outline_variant_light
    "0x010600c1": "#ff44464f",  # system_outline_variant_dark
    "0x010600c5": "#ffffffff",  # system_error_0
    "0x010600c6": "#fffffbff",  # system_error_10
    "0x010600c7": "#ffffedea",  # system_error_50
    "0x010600c8": "#ffffdad6",  # system_error_100
    "0x010600c9": "#ffffb4ab",  # system_error_200
    "0x010600ca": "#ffff897d",  # system_error_300
    "0x010600cb": "#ffff5449",  # system_error_400
    "0x010600cc": "#ffde3730",  # system_error_500
    "0x010600cd": "#ffba1a1a",  # system_error_600
    "0x010600ce": "#ff93000a",  # system_error_700
    "0x010600cf": "#ff690005",  # system_error_800
    "0x010600d0": "#ff410002",  # system_error_900
    "0x010600d1": "#ff000000",  # system_error_1000
}

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


def _parse_gradient(xml_out):
    """解析 aapt2 拆分出来的 <gradient> drawable（$xxx__0.xml），失败返回 None。"""
    elems = _parse_vector_elements(xml_out)
    if not elems or elems[0]["tag"] != "gradient":
        return None
    attrs = elems[0]["attrs"]
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
        grad = _parse_gradient(run_aapt2_dump_xmltree(apk_path, info["value"]))
        if grad:
            return ("gradient", grad)
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


def _draw_stroke(layer, subpaths, color, alpha, wpx, cap):
    """描边一条路径，端点按 strokeLineCap 处理。

    butt(0) 原样、round(1) 两端补圆、square(2) 沿首末线段方向各延长半个
    线宽（等价于方形端点）。旧实现只识别 round，square 被静默降级成 butt。

    拐角统一用 Pillow 的 round join 近似：ImageDraw 不提供 miter/bevel，
    Android 默认的 miter 在尖锐折角处会比这里略"尖"，属已知近似。
    """
    stroke = Image.new("RGBA", layer.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(stroke)
    col = (color[0], color[1], color[2], int(round(color[3] * alpha)))
    r = wpx / 2.0
    for pts in subpaths:
        if len(pts) < 2:
            continue
        draw_pts = _extend_square_caps(pts, r) if cap == 2 else pts
        d.line([(round(p[0]), round(p[1])) for p in draw_pts], fill=col, width=wpx, joint="curve")
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
                        # 描边宽度按完整变换（viewport 缩放 × group 缩放/旋转）换算，
                        # 不能只用 sx/sy，否则带 group scale 的图标描边会粗成实心块。
                        wpx = max(1, int(round(sw * _mat_scale(m))))
                        cap = _VECTOR_CAPS.get(_attr_enum(a.get("strokeLineCap", "butt")), 0)
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


def _normalize_icon_png(raw: bytes, size: int = _ICON_SIZE):
    """把任意可解码的位图字节统一成 size×size 的 PNG；解不了返回 None。

    位图图标旧实现直接导出 APK 里的原始文件，导出尺寸随资源密度变化，
    与自适应/矢量链路固定的 _ICON_SIZE² 不一致：同一个"导出图标"按钮
    对不同 APK 给出不同规格的文件。
    """
    try:
        with Image.open(io.BytesIO(raw)) as im:
            img = im.convert("RGBA").resize((size, size), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        logging.debug("位图图标转码为统一规格失败，回退原始字节", exc_info=True)
        return None


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


def extract_icon_bytes(apk_path, foreground, background, size=_ICON_SIZE, fg_scale=None, full_res=None, index=None):
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
    info["permissions"] = re.findall(r"uses-permission:\s+name='([^']+)'", text)

    # --- Feature ---
    info["features"] = re.findall(r"uses-feature:\s+name='([^']+)'", text)
    info["implied_features"] = re.findall(r"uses-implied-feature:\s+name='([^']+)'", text)

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

    # 少数 APK 没有 application-icon-* 行，只在 application 节点上有 icon 属性，
    # 此前这种情况会完全不显示图标。用"密度"0 占位，fill_info 取 max() 挑选
    # 最佳密度时不会被它盖过真实密度。
    if not info["icons"]:
        m_icon = re.search(r"^application:\s[^\n]*?icon='([^']*)'", text, re.M)
        if m_icon and m_icon.group(1):
            info["icons"]["0"] = m_icon.group(1)

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

class _Cancelled(Exception):
    """内部取消信号：请求被更新的请求覆盖、或窗口关闭时抛出让 run() 丢弃本轮。"""


class IconWorker(QtCore.QThread):
    """常驻的图标提取线程：只保留「最新一次请求」，旧请求自动作废。

    旧实现每次都新建 QThread 并 requestInterruption 旧线程，虽然结果有代数
    保护，但快速连续解析时线程与 aapt2 子进程会堆积（实测连续 20 次请求
    = 20 个线程同时在跑）。改为单线程 + 最新请求覆盖：

    - request() 由 UI 线程调用：写入待处理请求并唤醒工作线程，返回代数；
    - 工作线程每轮取走请求；运行期间通过 _check_cancel() 检测到有更新请求
      （或已请求停止）就抛 _Cancelled 提前放弃，再取最新请求；
    - 只有仍是当前代数的结果才会 emit，UI 侧再用 _icon_gen 做一次投递延迟
      校验（信号排队期间可能又来了新请求）。

    注意：不要命名为 finished——会遮蔽 QThread 内建 finished 信号，
    破坏 thread.finished.connect(deleteLater) 等惯用法。
    """
    iconReady = QtCore.pyqtSignal(QtGui.QImage, bytes, int)  # 成功（QImage 在槽内转 QPixmap；字节流供导出）
    failed = QtCore.pyqtSignal(str, int)  # 提取失败时发出，供 UI 可见提示

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cond = threading.Condition()
        self._pending = None      # (apk_path, icon_path, gen)
        self._gen = 0             # 最新请求代数
        self._current_gen = 0     # 正在处理的代数
        self._stopping = False

    # ---------------- UI 线程接口 ----------------
    def request(self, apk_path: str, icon_path: str) -> int:
        """登记一次提取请求（覆盖尚未开始的旧请求），返回本次代数。"""
        with self._cond:
            self._gen += 1
            self._pending = (apk_path, icon_path, self._gen)
            self._cond.notify_all()
            return self._gen

    def stop(self):
        """请求工作线程结束（关闭窗口时调用）。"""
        with self._cond:
            self._stopping = True
            self._pending = None
            self._cond.notify_all()

    # ---------------- 工作线程 ----------------
    def _take_pending(self):
        """取走待处理请求；返回 None 表示应退出线程。"""
        with self._cond:
            while not self._stopping and self._pending is None:
                self._cond.wait(0.5)
            if self._stopping:
                return None
            item, self._pending = self._pending, None
            self._current_gen = item[2]
            return item

    def _is_stale(self, gen: int) -> bool:
        with self._cond:
            return self._stopping or gen != self._gen

    def _check_cancel(self):
        """当前请求已过期（有新请求/窗口关闭）时抛出 _Cancelled。"""
        if self._is_stale(self._current_gen):
            raise _Cancelled

    @staticmethod
    def _load_image(img: QtGui.QImage, data: bytes) -> bool:
        """把字节载入 QImage；Qt 解不了时用 PIL 转成标准 PNG 再试一次。

        这里必须用 QImage 而不是 QPixmap：本方法在工作线程里执行，而
        QPixmap 属于 GUI 线程对象（在部分平台/后续 Qt 版本上于子线程使用
        属未定义行为）。转 QPixmap 的动作放在 GUI 线程的 on_icon_loaded 里。
        """
        if img.loadFromData(data):
            return True
        try:
            im = Image.open(io.BytesIO(data)).convert("RGBA")
            buf = io.BytesIO()
            im.save(buf, format="PNG")
            return bool(img.loadFromData(buf.getvalue()))
        except Exception:
            return False

    def _extract_adaptive_icon(self, apk_path: str, icon_path: str) -> bytes:
        """
        XML 图标提取（自适应图标或普通 VectorDrawable）：
        1) 根元素是 <vector> 时直接栅格化。部分 APK（实测月虹）会把
           mipmap/ic_launcher 直接指向一个普通矢量 drawable，它的
           viewport 里已经画好了完整图标，没有 foreground/background 层；
           旧实现只按 adaptive-icon 解析，找不到两层就判失败。
        2) 根元素是 <adaptive-icon> 时，从 xmltree 解析 foreground/background
           资源地址，完整解析每一层（支持混淆字符串引用、无扩展名文件、
           <scale> 包装），两层都能渲染（位图/颜色/矢量）时合成完整图标；
        3) 结构不是标准 adaptive-icon、或任一层渲染失败时，回退到
           icon xml 所属 mipmap 条目的最高密度位图（8.0 之前的传统图标）。

        `dump resources` 只在确实需要时执行（旧实现在拿到 fg/bg 地址前
        就 dump，非自适应图标也白白跑一次全量输出）。
        """
        self._check_cancel()
        xml_out = run_aapt2_dump_xmltree(apk_path, icon_path)

        root_m = re.search(r"E:\s*(\S+)\s*\(", xml_out or "")
        if root_m and root_m.group(1) == "vector":
            self._check_cancel()
            img = rasterize_vector_layer(apk_path, icon_path, _ICON_SIZE)
            if img is None:
                return b""
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()

        fg_addr = find_adaptive_layer_addr(xml_out, "foreground")
        bg_addr = find_adaptive_layer_addr(xml_out, "background")

        full_res = None
        index = None
        if fg_addr and bg_addr:
            full_res = run_aapt2_dump_resource(apk_path)
            self._check_cancel()
            # 一次性索引全量输出，后续所有资源条目查询 O(1)
            index = _ResourceIndex(full_res)
            fg_kind, fg_val, fg_scale = resolve_icon_layer(apk_path, full_res, fg_addr, index=index)
            bg_kind, bg_val, _bg_scale = resolve_icon_layer(apk_path, full_res, bg_addr, index=index)
            self._check_cancel()
            if fg_kind in ("image", "color", "vector") and bg_kind in ("image", "color", "vector"):
                try:
                    return extract_icon_bytes(
                        apk_path,
                        {"type": fg_kind, "value": fg_val},
                        {"type": bg_kind, "value": bg_val},
                        fg_scale=fg_scale,
                        full_res=full_res,
                        index=index,
                    )
                except _Cancelled:
                    raise
                except Exception as e:
                    # 层解析成功不代表能渲染：前景/背景可能是 <bitmap>、<shape>、
                    # <animated-vector> 或 res/color 状态列表等根节点，栅格化会失败。
                    # 这种情况下继续走下面的位图回退，而不是把整个图标判为失败。
                    logging.warning("合成自适应图标失败，改用位图回退: %s", e)

        # 回退：找 icon xml 所属 mipmap 条目的最高密度位图
        self._check_cancel()
        if full_res is None:
            full_res = run_aapt2_dump_resource(apk_path)
            self._check_cancel()
            index = _ResourceIndex(full_res)
        fallback = find_mipmap_fallback(full_res, icon_path, index)
        if fallback:
            with zipfile.ZipFile(apk_path, "r") as zf:
                img = Image.open(zf.open(fallback)).convert("RGBA")
            img = img.resize((_ICON_SIZE, _ICON_SIZE), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        return b""

    def _extract(self, apk_path: str, icon_path: str):
        """执行一次提取，返回 (QImage, 导出用 PNG 字节)。"""
        img = QtGui.QImage()
        data = b""
        if icon_path.lower().endswith(('.png', '.jpg', '.jpeg', '.webp', '.gif')):
            with zipfile.ZipFile(apk_path, "r") as zf:
                raw = zf.open(icon_path).read()
            # 与自适应/矢量链路统一导出规格（_ICON_SIZE²）；PIL 解不了时
            # 保留原始字节，交给 Qt 解码器兜底。
            data = _normalize_icon_png(raw) or raw
            if not self._load_image(img, data):
                raise ValueError(f"图标文件无法解码为图片: {icon_path}")

        elif icon_path.lower().endswith('.xml'):
            data = self._extract_adaptive_icon(apk_path, icon_path)
            if not data:
                raise ValueError("自适应图标的前景/背景均无法渲染，且未找到位图回退图标")
            if not self._load_image(img, data):
                raise ValueError("合成后的图标无法解码为图片")
        else:
            raise ValueError(f"不支持的图标类型: {icon_path}")
        return img, data

    def run(self):
        """工作线程主循环：不断取最新请求执行，直到 stop()。"""
        while True:
            item = self._take_pending()
            if item is None:
                return
            apk_path, icon_path, gen = item
            try:
                self._check_cancel()
                image, data = self._extract(apk_path, icon_path)
            except _Cancelled:
                continue  # 已有更新的请求（或窗口关闭）：丢弃这次结果
            except Exception as e:
                logging.exception("子线程提取图标失败: %s", e)
                if not self._is_stale(gen):
                    self.failed.emit(str(e), gen)
                continue
            if not self._is_stale(gen):
                self.iconReady.emit(image, data, gen)

class ApkInfoWorker(QtCore.QThread):
    """后台线程：运行 aapt2 dump badging，避免阻塞 UI"""
    resultReady = QtCore.pyqtSignal(str)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, apk_path, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path

    def run(self):
        # closeEvent 会 requestInterruption()：旧实现从不检查，中断请求形同虚设，
        # 只能靠 kill_running_aapt2() 兜底。这里在起子进程前和投递结果前各检查一次。
        if self.isInterruptionRequested():
            return
        try:
            output = run_aapt2_dump_badging(self.apk_path)
        except FileNotFoundError as e:
            self.failed.emit(str(e))
            return
        except Exception as e:
            self.failed.emit(f"执行 aapt2 失败：\n{e}")
            return
        if self.isInterruptionRequested():
            return  # 关窗途中：结果不再投递（控件随时可能被销毁）
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


def _sanitize_apk_name(name: str) -> str:
    """把应用名/用户输入整理成合法的 APK 文件名（含 .apk 扩展名）。

    - 非法字符（\\ / : * ? " < > | 与控制字符）替换为下划线；
    - 去掉结尾的点和空格：Windows 会静默丢弃它们，生成的文件名与预期不符；
    - 保留设备名（CON / NUL / COM1 …）加下划线前缀规避；
    - 全部被清理掉时返回空串，由调用方提示"没有生成新的文件名"。
    """
    stem = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", (name or "").strip())
    if stem.lower().endswith(".apk"):
        stem = stem[:-4]
    stem = stem.rstrip(" .")
    if not stem:
        return ""
    if stem.upper() in _RESERVED_NAMES:
        stem = "_" + stem
    return stem + ".apk"


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("APK 信息查看器（aapt2）")
        self.setWindowIcon(QtGui.QIcon(local_resource_path("resources/logo.ico")))
        self.resize(700, 700)
        self._busy = False
        # 当前已解析 APK 的路径：process_apk 显式记录，不再靠回读输入框
        self._apk_path = ""
        # 线程对象必须长期持有引用：若线程仍在运行时 Python 引用被替换/回收，
        # PyQt 会在 QThread 析构时报 "QThread: Destroyed while thread is still running"。
        self._apk_workers = []
        # 图标提取是常驻线程（单线程 + 最新请求覆盖），首次使用时创建
        self._icon_worker = None
        self._icon_gen = 0  # 最近一次图标请求的代数，用于丢弃延迟投递的旧结果
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # 顶部：文件选择/拖放
        file_row = QtWidgets.QHBoxLayout()
        self.apk_path_edit = DropLineEdit()
        self.apk_path_edit.fileDropped.connect(self.process_apk)
        # 输入框是可编辑的：手输/粘贴路径后回车即解析（此前只能走文件对话框）
        self.apk_path_edit.returnPressed.connect(self._parse_typed_path)
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
        icon_row.addWidget(QtWidgets.QLabel("APP图标："))
        icon_row.addSpacing(15)
        icon_row.addWidget(self.icon_label)
        icon_row.addSpacing(50)
        icon_row.addWidget(self.btn_export_icon)

        # 图标状态就地提示：失败原因不弹模态对话框，避免批量拖入时反复打断
        self.lbl_icon_hint = QtWidgets.QLabel("")
        self.lbl_icon_hint.setStyleSheet("color: #a05a00;")
        icon_row.addWidget(self.lbl_icon_hint)

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
        # 允许就地微调：do_rename 会重新净化非法字符，回车等同点击"执行重命名"
        self.rename_preview.setPlaceholderText("可直接修改文件名后执行重命名")
        self.rename_preview.returnPressed.connect(self.do_rename)
        btn_rename = QtWidgets.QPushButton("执行重命名")
        btn_rename.clicked.connect(self.do_rename)
        rename_layout.addWidget(self.rename_preview, stretch=1)
        rename_layout.addWidget(btn_rename)
        layout.addWidget(rename_group)

        # 原始输出
        # raw_group = QtWidgets.QGroupBox("aapt2 原始输出")
        # vg = QtWidgets.QVBoxLayout(raw_group)
        self.te_raw = QtWidgets.QPlainTextEdit()
        self.te_raw.setReadOnly(True)
        self.te_raw.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        # vg.addWidget(self.te_raw)
        # layout.addWidget(raw_group, stretch=1)

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
        te.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(te)
        return {"group": group, "edit": te}

    def browse_apk(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "选择 APK 文件", "", "APK 文件 (*.apk)"
        )
        if path:
            self.apk_path_edit.setText(path)
            self.process_apk(path)

    def _parse_typed_path(self):
        """输入框回车：按框里的路径直接解析（手输/粘贴路径的入口）。"""
        self.process_apk(self.apk_path_edit.text().strip())

    def _current_apk_path(self) -> str:
        """当前解析结果对应的 APK 路径。

        优先用 process_apk 记录的路径：调用方（拖放、命令行等）不一定已经
        把路径同步到输入框，回读输入框会导致这类调用完全提取不到图标。
        """
        return self._apk_path or self.apk_path_edit.text().strip()

    def process_apk(self, path: str):
        if not path or not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(self, "提示", "请选择有效的 APK 文件。")
            return
        if self._busy:
            QtWidgets.QMessageBox.information(self, "提示", "正在解析 APK，请稍候再试。")
            return
        self._apk_path = path
        try:
            self.set_busy(True)
            self._prune_workers()
            worker = ApkInfoWorker(path)
            self._apk_workers.append(worker)
            worker.resultReady.connect(self.on_apk_info_ready)
            worker.failed.connect(self.on_apk_info_failed)
            worker.start()
        except Exception as e:
            logging.exception("启动解析线程失败: %s", e)
            self.set_busy(False)  # 否则界面会一直停在"忙碌"状态
            QtWidgets.QMessageBox.critical(self, "错误", f"启动解析任务失败：\n{e}")

    def set_busy(self, busy: bool):
        self._busy = busy
        self.btn_refresh.setEnabled(not busy)
        self.btn_export_icon.setEnabled(not busy)
        self.btn_browse.setEnabled(not busy)
        self.apk_path_edit.setEnabled(not busy)
        if busy:
            self.setCursor(QtCore.Qt.CursorShape.WaitCursor)
            self.te_raw.setPlainText("正在解析 APK，请稍候…")
        else:
            self.unsetCursor()

    def _prune_workers(self):
        """清理已结束的解析线程对象；运行中的保留引用，防止 QThread 被 GC 时崩溃。"""
        for t in [t for t in self._apk_workers if not t.isRunning()]:
            t.deleteLater()
            self._apk_workers.remove(t)

    def _start_icon_worker(self, apk_path: str, icon_path: str):
        """把图标提取请求交给常驻线程，最新请求覆盖旧请求。

        单线程 + 代数丢弃：连续解析多个 APK 时不会堆积线程与 aapt2 子进程，
        UI 线程也不做任何等待（旧实现最多 wait(5000) 卡 5 秒，后来的实现则是
        每请求起一个线程）。
        """
        if self._icon_worker is None:
            self._icon_worker = IconWorker()
            self._icon_worker.iconReady.connect(self.on_icon_loaded)
            self._icon_worker.failed.connect(self.on_icon_failed)
            self._icon_worker.start()
        self._icon_gen = self._icon_worker.request(apk_path, icon_path)

    def _stop_icon_worker(self):
        """请求常驻图标线程结束（关闭窗口/退出时调用）。"""
        if self._icon_worker is not None:
            self._icon_worker.stop()

    def closeEvent(self, event):
        """关闭窗口前取消后台线程，并强制结束卡住的 aapt2 子进程。

        不使用 QThread.terminate()：Qt 明确说明它不安全（可能死锁或崩溃）。
        这里先 kill 子进程，工作线程会立刻从 aapt2 调用返回并在下一个
        取消检查点退出，因此只需有界等待。
        """
        self._stop_icon_worker()
        threads = list(self._apk_workers)
        for t in threads:
            if t.isRunning():
                t.requestInterruption()
        kill_running_aapt2()
        wait_list = threads + ([self._icon_worker] if self._icon_worker else [])
        # 所有线程共用一个等待预算：旧实现逐个 wait(5s)，最坏耗时是 N×5s
        deadline = time.monotonic() + _CLOSE_WAIT_MS / 1000.0
        for t in wait_list:
            if not t.isRunning():
                continue
            remain_ms = int((deadline - time.monotonic()) * 1000)
            if remain_ms <= 0 or not t.wait(remain_ms):
                logging.warning("后台线程未在 %d ms 内结束，交由退出流程收尾", _CLOSE_WAIT_MS)
                break
        event.accept()

    def shutdown_background(self, timeout_ms: int = 10000) -> bool:
        """退出前等待后台线程真正结束。

        QThread 在运行中被析构会让进程崩溃，因此事件循环结束后仍要确认。
        返回是否全部结束。
        """
        self._stop_icon_worker()
        kill_running_aapt2()
        all_done = True
        for t in self._apk_workers + ([self._icon_worker] if self._icon_worker else []):
            if t.isRunning() and not t.wait(timeout_ms):
                logging.warning("后台线程仍在运行，等待超时: %s", t)
                all_done = False
        return all_done

    def on_apk_info_ready(self, output: str):
        try:
            self.te_raw.setPlainText(output)
            info = parse_aapt2_output(output)
            self.fill_info(info)
        except Exception as e:
            # slot 内未捕获异常会让 PyQt6 直接 qFatal() 结束进程，必须自行兜住
            logging.exception("处理 aapt2 输出失败: %s", e)
            QtWidgets.QMessageBox.critical(self, "错误", f"解析 APK 信息失败：\n{e}")
        finally:
            # 无论成功失败都要恢复界面，否则按钮会永久禁用
            self.set_busy(False)

    def on_apk_info_failed(self, message: str):
        QtWidgets.QMessageBox.critical(self, "错误", message)
        self.set_busy(False)

    def reparse_current(self):
        text = self.te_raw.toPlainText()
        if not text.strip():
            return
        try:
            info = parse_aapt2_output(text)
            self.fill_info(info)
        except Exception as e:
            logging.exception("重新解析失败: %s", e)
            QtWidgets.QMessageBox.critical(self, "错误", f"重新解析失败：\n{e}")

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
        apk_path = self._current_apk_path()
        if apk_path and os.path.isfile(apk_path):
            try:
                icons = info.get("icons", {})
                if icons:
                    # 选择最大 density 的 icon
                    best = max(icons.items(), key=lambda x: int(x[0]))
                    icon_path = best[1]

                    self.icon_label.clear()  # 先清空（含上次失败提示文本）
                    self.lbl_icon_hint.clear()
                    self._start_icon_worker(apk_path, icon_path)
            except Exception as e:
                logging.exception("提取图标失败: %s", e)

        # 生成重命名预览
        app_name = self.le_app_name.text().strip() or "App"
        ver_text = info.get('version_name', '').strip() or "0.0"
        self.rename_preview.setText(_sanitize_apk_name(f"{app_name}_{ver_text}"))

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
        lines.append("")
        lines.append("[其它关键信息]")
        lines.append(self.te_other["edit"].toPlainText() or "(无)")

        summary = "\n".join(lines)
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(summary)
        QtWidgets.QMessageBox.information(self, "已复制", "已复制摘要到剪贴板。")

    def do_rename(self):
        old_path = self._current_apk_path()
        # 预览框现在可编辑：重新净化，非法字符/保留设备名不能带进 os.replace
        new_name = _sanitize_apk_name(self.rename_preview.text())
        if not old_path or not os.path.isfile(old_path):
            QtWidgets.QMessageBox.warning(self, "提示", "未选择有效的 APK 文件。")
            return
        if not new_name:
            QtWidgets.QMessageBox.warning(self, "提示", "没有生成新的文件名。")
            return
        self.rename_preview.setText(new_name)  # 回显净化后的名字
        new_path = str(Path(old_path).with_name(new_name))
        if os.path.abspath(new_path) == os.path.abspath(old_path):
            return
        if os.path.exists(new_path):
            ret = QtWidgets.QMessageBox.question(
                self, "覆盖确认",
                f"目标文件已存在：\n{new_path}\n\n是否覆盖？",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                QtWidgets.QMessageBox.StandardButton.No,
            )
            if ret != QtWidgets.QMessageBox.StandardButton.Yes:
                return
        try:
            # os.rename 在 Windows 上目标已存在时失败；os.replace 原子替换
            os.replace(old_path, new_path)
            QtWidgets.QMessageBox.information(self, "完成", f"已重命名为:\n{new_path}")
            self._apk_path = new_path
            self.apk_path_edit.setText(new_path)
            self.rename_preview.setText(new_name)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"重命名失败: {e}")

    def on_icon_loaded(self, image: QtGui.QImage, data: bytes, gen: int):
        if gen != self._icon_gen:
            return  # 过期结果（用户已开始解析新 APK），丢弃
        # QPixmap 只能在 GUI 线程构造：工作线程发来的是 QImage，在这里转换
        pix = QtGui.QPixmap.fromImage(image)
        self.icon_label.setScaledContents(True)  # 提示文字时要关掉，见 on_icon_failed
        self.icon_label.setPixmap(pix)
        self.lbl_icon_hint.clear()
        self.lbl_icon_hint.setToolTip("")
        if not pix.isNull():
            self._current_icon_bytes = data
            self.btn_export_icon.setVisible(True)
        else:
            self._current_icon_bytes = None
            self.btn_export_icon.setVisible(False)

    def on_icon_failed(self, message: str, gen: int):
        """图标提取失败：就地文字提示（非模态），详情放 tooltip 与日志。

        旧实现每次失败都弹 QMessageBox.warning，连续拖入多个 APK 时会
        反复打断用户；这里改成不阻塞的提示。
        """
        if gen != self._icon_gen:
            return
        logging.warning("图标提取失败: %s", message)
        # 关掉 scaledContents：否则"提取失败"四个字会被拉伸放大到整个 96×96
        self.icon_label.setScaledContents(False)
        self.icon_label.setText("提取失败")
        self.icon_label.setToolTip(f"图标提取失败：{message}")
        brief = (message or "").strip().splitlines()[0] if (message or "").strip() else "未知原因"
        if len(brief) > 48:
            brief = brief[:47] + "…"
        self.lbl_icon_hint.setText(f"图标提取失败：{brief}")
        self.lbl_icon_hint.setToolTip(f"图标提取失败：\n{message}")
        self._current_icon_bytes = None
        self.btn_export_icon.setVisible(False)

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
            "基于 PyQt6 + aapt2 的图形化<br>"
            "解析 APK 文件信息的工具程序<br><br>"
            '更多信息: <a href="https://github.com/Sinryou/WinApkInfo">项目主页</a><br>'
            f"版本: {__version__}<br>"
            "Copyright (c) 2025-2026 Sinryou.<br>At MIT License."
        )

class _ErrorDialog(QtCore.QObject):
    """把非 GUI 线程的未捕获异常投递到 GUI 线程弹窗。

    必须先在 GUI 线程构造，signal/slot 的队列连接才会把槽函数派发回 GUI
    线程；否则等于在子线程里操作控件。
    """

    requested = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.requested.connect(self._show, QtCore.Qt.ConnectionType.QueuedConnection)

    @QtCore.pyqtSlot(str)
    def _show(self, text: str):
        QtWidgets.QMessageBox.critical(None, "未预期的错误", text)


# 在 GUI 线程创建的异常提示器（见 install_excepthook），模块级引用防止被回收
_error_dialog = None


def _on_gui_thread() -> bool:
    """当前线程是否 Qt GUI 线程（控件只能在 GUI 线程上使用）。"""
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return QtCore.QThread.currentThread() is app.thread()


def install_excepthook():
    """安装全局异常钩子，避免未捕获异常让进程"静默消失"。

    PyQt6 在 slot 里抛出未捕获的 Python 异常时会调用 qFatal() 直接结束
    进程；打包配置是 console=False，用户既看不到 traceback 也看不到提示。
    这里把异常写进日志并弹窗，作为各 slot 自身 try/except 之外的兜底。

    sys.excepthook 运行在**抛出异常的那个线程**里，而 QMessageBox 只能在
    GUI 线程使用：实测在子线程直接弹窗会以 0xC0000005（访问违例）崩溃，
    只写日志的钩子则能让进程正常存活。因此非 GUI 线程只记日志，GUI 线程
    才直接弹窗；有 QApplication 时子线程的异常经队列投递回主线程再提示。
    """
    global _error_dialog
    if _error_dialog is None and QtWidgets.QApplication.instance() is not None:
        _error_dialog = _ErrorDialog()

    def _hook(exc_type, exc, tb):
        logging.critical("未捕获异常", exc_info=(exc_type, exc, tb))
        text = f"{exc_type.__name__}: {exc}\n\n详细信息见日志文件。"
        if _on_gui_thread():
            try:
                QtWidgets.QMessageBox.critical(None, "未预期的错误", text)
            except Exception:
                pass
        elif _error_dialog is not None:
            # 队列连接：真正的弹窗发生在 GUI 线程，这里只投递
            _error_dialog.requested.emit(text)

    sys.excepthook = _hook


def _self_test(apk_path: str = None) -> int:
    """打包后自检（`WinApkInfo.exe --self-test [apk]`），供构建管线验证产物。

    不创建 QApplication，只检查运行时依赖与随包资源：aapt2 可执行、
    resources/ 下的图标与 SDK 表齐全。传入 APK 时还会走一遍真实的
    badging → 最佳密度 → 图标提取链路，验证 aapt2 与图片解码在打包
    环境下确实可用。窗口模式没有控制台，构建脚本只依据退出码判断；
    失败详情写入日志文件。
    """
    problems = []
    aapt2_path = None
    try:
        aapt2_path = find_aapt2()
        rc, out, err = _run_aapt2([aapt2_path, "version"], timeout=30)
        if rc != 0:
            detail = (_decode_output(err or out)).strip() or f"退出码 {rc}"
            problems.append(f"aapt2 无法运行：{detail}")
    except Exception as e:
        problems.append(f"找不到可用的 aapt2：{e}")

    for rel in ("resources/android_sdk_versions.json", "resources/logo.ico", "resources/info.png"):
        path = local_resource_path(rel)
        if not os.path.isfile(path):
            problems.append(f"缺少随包资源：{path}")

    try:
        if not load_sdk_versions():
            problems.append("SDK 版本表为空或无法解析")
    except Exception as e:
        problems.append(f"读取 SDK 版本表失败：{e}")

    if apk_path:
        try:
            info = parse_aapt2_output(run_aapt2_dump_badging(apk_path))
            icons = info.get("icons") or {}
            if not icons:
                problems.append(f"样本 APK 没有可用图标：{apk_path}")
            else:
                icon_path = max(icons.items(), key=lambda item: int(item[0]))[1]
                image, data = IconWorker()._extract(apk_path, icon_path)
                if image.isNull() or not data:
                    problems.append(f"样本 APK 图标提取结果为空：{icon_path}")
                else:
                    logging.info("自检图标提取通过：%s -> %d 字节", icon_path, len(data))
        except Exception as e:
            problems.append(f"样本 APK 图标提取失败：{e}")

    if problems:
        for problem in problems:
            logging.error("自检失败：%s", problem)
        return 1
    logging.info("自检通过：aapt2=%s", aapt2_path)
    return 0


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

    # 构建/排障入口：--version 输出版本，--self-test 检查打包产物是否完整
    if "--version" in sys.argv:
        if sys.stdout is not None:
            print(__version__)
        return 0
    if "--self-test" in sys.argv:
        index = sys.argv.index("--self-test")
        apk_path = None
        if index + 1 < len(sys.argv) and not sys.argv[index + 1].startswith("-"):
            apk_path = sys.argv[index + 1]
        return _self_test(apk_path)

    # 高分屏适配：Qt6 默认启用 high-DPI 缩放（AA_EnableHighDpiScaling /
    # AA_UseHighDpiPixmaps 已废弃），无需再设置任何属性。

    app = QtWidgets.QApplication(sys.argv)
    # 必须在 QApplication 之后：钩子要用主线程创建的提示器做跨线程投递
    install_excepthook()
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    code = app.exec()
    # 事件循环结束后必须确认后台线程已退出：QThread 运行中被析构会让进程崩溃
    w.shutdown_background()
    return code


if __name__ == "__main__":
    sys.exit(main())
