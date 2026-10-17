# -*- coding: utf-8 -*-
"""aapt2 子进程执行、输出解码与多级缓存。"""
import os
import sys
import subprocess
import threading
import time
import hashlib
import tempfile
import logging
import shutil
import functools
from pathlib import Path

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
    """磁盘缓存目录；设置 WINAPKINFO_NO_DISK_CACHE=1 可禁用。

    规范化使用各操作系统标准的应用缓存目录：
    - Windows: %LOCALAPPDATA%/WinApkInfo/cache
    - Linux/macOS: QStandardPaths.CacheLocation 或 ~/.cache/WinApkInfo
    避免写入系统临时目录 tempfile.gettempdir() 后被 Windows 磁盘清理/存储感知程序频繁误删。
    """
    if os.environ.get("WINAPKINFO_NO_DISK_CACHE"):
        return None

    # Windows 平台标准应用缓存目录
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return os.path.join(local_app_data, "WinApkInfo", "cache")

    # 非 Windows 或未定义 LOCALAPPDATA 时，优先借助 QStandardPaths
    try:
        from PyQt6.QtCore import QStandardPaths
        base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.CacheLocation)
        if base:
            return os.path.join(base, "WinApkInfo", "cache") if "winapkinfo" not in base.lower() else base
    except Exception:
        pass

    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        return os.path.join(xdg_cache, "WinApkInfo")

    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".cache")):
        return os.path.join(home, ".cache", "WinApkInfo")

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


@functools.lru_cache(maxsize=1)
def find_aapt2() -> str:
    """
    优先在脚本同级目录查找 aapt2 / aapt2.exe；否则使用系统 PATH 中的 aapt2。
    找不到则抛出 FileNotFoundError。

    结果用 lru_cache 缓存：一次图标提取可能发起多次 dump，每次都重新探测
    候选文件并搜索 PATH 属于纯浪费（抛出的异常不会被缓存，装好 aapt2 后
    仍可重新探测）。
    """
    # 兼容单文件/模块化部署：以项目根目录为基准候选查找
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))  # 支持 PyInstaller
    candidates = [
        here / "aapt2", here / "aapt2.exe", here / "tools" / "aapt2.exe",
        Path(__file__).resolve().parent / "aapt2.exe",
    ]
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


def get_disk_cache_info() -> dict:
    """返回磁盘缓存统计信息：{'dir': str, 'count': int, 'total_bytes': int, 'total_mb': float}。"""
    disk_dir = _default_disk_cache_dir()
    if not disk_dir or not os.path.isdir(disk_dir):
        return {"dir": disk_dir or "", "count": 0, "total_bytes": 0, "total_mb": 0.0}
    try:
        names = [n for n in os.listdir(disk_dir) if n.endswith(".txt")]
        total = sum(os.path.getsize(os.path.join(disk_dir, n)) for n in names)
        return {
            "dir": disk_dir,
            "count": len(names),
            "total_bytes": total,
            "total_mb": round(total / (1024 * 1024), 2),
        }
    except Exception as e:
        logging.warning("获取磁盘缓存信息失败: %s", e)
        return {"dir": disk_dir, "count": 0, "total_bytes": 0, "total_mb": 0.0}


def clear_disk_cache() -> int:
    """清空磁盘缓存与内存缓存，返回释放的字节数。"""
    _aapt2_cache.clear()
    disk_dir = _default_disk_cache_dir()
    if not disk_dir or not os.path.isdir(disk_dir):
        return 0
    freed = 0
    try:
        for n in os.listdir(disk_dir):
            if n.endswith(".txt") or n.startswith(".tmp"):
                p = os.path.join(disk_dir, n)
                try:
                    freed += os.path.getsize(p)
                    os.remove(p)
                except OSError:
                    pass
    except Exception as e:
        logging.warning("清空磁盘缓存失败: %s", e)
    return freed
