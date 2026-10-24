# -*- coding: utf-8 -*-
"""后台解析工作线程（ApkInfoWorker、IconWorker，基于标准 Qt Worker-Object 架构）。"""
import io
import threading
import logging
import re
from PIL import Image
from PyQt6 import QtCore, QtGui

from core.aapt import (
    kill_running_aapt2, run_aapt2_dump_badging, run_aapt2_dump_resource,
    run_aapt2_dump_xmltree
)
from core.resources import (
    extract_resource_entry, get_resource_index, get_resource_info,
    open_apk_zip, sniff_file_kind, BITMAP_EXTS
)
from core.vector import rasterize_vector_layer, vector_uses_resources
from core.apk_parser import (
    ICON_SIZE, compose_adaptive_icon, decode_icon_image, find_adaptive_layer_addr,
    find_mipmap_fallback, normalize_icon_image, resolve_icon_layer, to_png_bytes
)

class _Cancelled(Exception):
    """内部取消信号：请求被更新的请求覆盖、或窗口关闭时抛出让工作者丢弃本轮。"""


class _IconWorkerCore(QtCore.QObject):
    """在工作线程中实际执行图标提取的 Worker Object。

    遵循 Qt 官方推荐的标准 Worker-Object 模式：
    - 作为 QObject 实体，通过 moveToThread 移入工作线程中执行；
    - 无 UI 控件依赖，槽函数 _do_work 运行在工作线程独立的 Qt 事件循环中；
    - 请求通过 Qt 队列连接（QueuedConnection）跨线程派发，彻底消除 threading.Condition
      忙等、轮询与裸锁等待；
    - 针对连续快速请求，支持代数（Generation）自增与最新请求覆盖，自动丢弃过期未完成任务。
    """
    iconReady = QtCore.pyqtSignal(QtGui.QImage, bytes, int)
    failed = QtCore.pyqtSignal(str, int)
    _trigger = QtCore.pyqtSignal()

    def __init__(self, owner):
        super().__init__()
        self._owner = owner
        self._lock = threading.Lock()
        self._pending = None      # (apk_path, icon_path, gen)
        self._gen = 0             # 最新请求代数
        self._current_gen = 0     # 正在处理的代数
        self._stopping = False
        self._working = False     # 是否正在执行提取（含待办刚被取走的阶段）
        self._trigger.connect(self._do_work, QtCore.Qt.ConnectionType.QueuedConnection)

    def request(self, apk_path: str, icon_path: str) -> int:
        """登记一次提取请求（最新请求覆盖尚未开始的旧请求），返回本次代数。"""
        with self._lock:
            self._gen += 1
            self._pending = (apk_path, icon_path, self._gen)
            gen = self._gen
        self._trigger.emit()
        return gen

    def stop(self):
        """请求工作线程停止，清空尚未处理的待办请求。"""
        with self._lock:
            self._stopping = True
            self._pending = None

    def cancel(self):
        """作废在途/待办的提取任务，但保持线程继续运行。

        新一轮解析开始时调用：当前文件已经换掉，上一个 APK 的图标任务
        没有继续的必要。推进代数可让正在执行的提取在下个取消检查点提前
        退出，也保证它完成后的结果不会再被投递（配合 UI 侧代数校验）。
        """
        with self._lock:
            self._gen += 1
            self._pending = None

    def is_stale(self, gen: int) -> bool:
        with self._lock:
            return self._stopping or gen != self._gen

    def is_busy(self) -> bool:
        """是否有提取任务在途（含刚被取走、尚未开始的待办）。"""
        with self._lock:
            return self._working or self._pending is not None

    def check_cancel(self):
        """当前请求已过期（有新请求/窗口关闭）时抛出 _Cancelled。"""
        with self._lock:
            stale = self._stopping or self._current_gen != self._gen
        if stale or self._owner.isInterruptionRequested():
            raise _Cancelled

    @QtCore.pyqtSlot()
    def _do_work(self):
        """工作线程槽函数：由 Qt 事件循环自动调度处理。"""
        with self._lock:
            if self._stopping or self._pending is None:
                return
            apk_path, icon_path, gen = self._pending
            self._pending = None
            self._current_gen = gen
            # 与取待办在同一把锁内置位：重命名前调用 is_busy() 时不会
            # 漏掉“待办已被取走、马上开始提取”的窗口。
            self._working = True

        try:
            if self.is_stale(gen) or self._owner.isInterruptionRequested():
                return

            try:
                self.check_cancel()
                image, data = self._owner._extract(apk_path, icon_path)
            except _Cancelled:
                return  # 已有更新请求或已中断：丢弃本轮结果
            except Exception as e:
                logging.exception("子线程提取图标失败: %s", e)
                if not self.is_stale(gen):
                    self.failed.emit(str(e), gen)
                return

            if not self.is_stale(gen):
                self.iconReady.emit(image, data, gen)
        finally:
            with self._lock:
                self._working = False


def _never_cancelled():
    """缺省取消检查回调：永不取消（--self-test 等无线程场景）。"""
    return False


def _load_image(img: QtGui.QImage, data: bytes) -> bool:
    """把字节载入 QImage；Qt 解不了时用 PIL 转成标准 PNG 再试一次。

    这里必须用 QImage 而不是 QPixmap：本函数在工作线程里执行，而
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


def _qimage_from_pil(im: Image.Image) -> QtGui.QImage:
    """PIL RGBA Image → QImage：像素直接搬运，不经 PNG 编码/解码。

    QImage 构造函数不接管外部缓冲的生命周期，copy() 一次把像素拷进
    Qt 自有内存后，中间字节缓冲即可释放。
    """
    if im.mode != "RGBA":
        im = im.convert("RGBA")
    buf = im.tobytes("raw", "RGBA")
    qimg = QtGui.QImage(buf, im.width, im.height, im.width * 4,
                        QtGui.QImage.Format.Format_RGBA8888)
    return qimg.copy()


def _icon_kind(apk_path: str, icon_path: str, zf=None):
    """按后缀/魔数判断图标是位图还是 XML。

    混淆包（AndResGuard 等）的资源路径可能完全没有扩展名，此时不能只靠
    endswith 分派，否则明明能读取的图标会被判成"不支持的类型"。
    """
    lower = icon_path.lower()
    if lower.endswith(BITMAP_EXTS):
        return "image"
    if lower.endswith(".xml"):
        return "xml"
    try:
        return sniff_file_kind(apk_path, icon_path, zf=zf)
    except Exception as e:
        logging.debug("图标类型嗅探失败 %s: %s", icon_path, e)
        return None


def _adaptive_layers_need_index(full_res: str, *addrs) -> bool:
    """自适应图标的层是否需要在解析前建全量资源索引。

    绝大多数图标的 fg/bg 直接是 color/image；此时只为两个地址各做一次
    线性查询就够了，构建整张索引反而更慢（15MB 资源表实测 0.4s vs 0.12s）。
    只有层值本身还是别名、字符串文件或矢量时，后续可能继续解引用，才值得
    建索引。
    """
    if not full_res:
        return False
    for addr in addrs:
        kind = get_resource_info(extract_resource_entry(full_res, addr))["type"]
        if kind in ("ref", "string_file", "vector"):
            return True
    return False


def _adaptive_icon_result(apk_path: str, icon_path: str, check, zf=None):
    """XML 图标提取（自适应图标或普通 VectorDrawable），返回 (PIL Image, 导出用 PNG 字节)。

    1) 根元素是 <vector> 时直接栅格化。部分 APK（实测月虹）会把
       mipmap/ic_launcher 直接指向一个普通矢量 drawable，它的
       viewport 里已经画好了完整图标，没有 foreground/background 层；
    2) 根元素是 <adaptive-icon> 时，从 xmltree 解析 foreground/background
       资源地址，完整解析每一层（支持混淆字符串引用、无扩展名文件、
       <scale> 包装），两层都能渲染（位图/颜色/矢量）时合成完整图标；
    3) 结构不是标准 adaptive-icon、或任一层渲染失败时，回退到
       icon xml 所属 mipmap 条目的最高密度位图（8.0 之前的传统图标）。

    `dump resources` 只在确实需要时执行。check 为取消检查回调，请求
    过期时抛 _Cancelled。Image 供显示直接转 QImage；导出字节随图像
    一次成型，不再"编码成 PNG 交调用方解码回来"。
    """
    check()
    xml_out = run_aapt2_dump_xmltree(apk_path, icon_path)

    root_m = re.search(r"E:\s*(\S+)\s*\(", xml_out or "")
    if root_m and root_m.group(1) == "vector":
        check()
        # 纯字面量颜色的矢量图标不需要资源表：直接交给渲染层，省掉大包
        # 上一次 1–2s 的 dump resources。只有 fill/stroke 引用资源时才建
        # 索引，避免每个引用重复线性扫描几十 MB 的 dump。
        full_res = None
        index = None
        if vector_uses_resources(xml_out):
            full_res = run_aapt2_dump_resource(apk_path)
            if full_res is None:
                # 本次图标提取已经尝试过资源表 dump 且失败。空串是"已尝试、
                # 无数据"的哨兵：渲染层看到它不会再把每个颜色引用都重跑一次
                # aapt2（一次 60s 超时会被放大成 N×60s）。
                full_res = ""
            index = get_resource_index(full_res)
        img = rasterize_vector_layer(apk_path, icon_path, ICON_SIZE, full_res, index)
        if img is None:
            return None, b""
        return img, to_png_bytes(img)

    fg_addr = find_adaptive_layer_addr(xml_out, "foreground")
    bg_addr = find_adaptive_layer_addr(xml_out, "background")

    full_res = None
    index = None
    if fg_addr and bg_addr:
        full_res = run_aapt2_dump_resource(apk_path)
        if full_res is None:
            full_res = ""  # 已尝试且失败：禁止回退阶段重复 dump
        check()
        # 只有层值还需要继续解引用（别名/字符串文件/矢量）时才构建全量
        # 索引；直接的 color/image 层用两次线性查询即可，索引反而更慢。
        if _adaptive_layers_need_index(full_res, fg_addr, bg_addr):
            index = get_resource_index(full_res)
        fg_kind, fg_val, fg_scale = resolve_icon_layer(apk_path, full_res, fg_addr, index=index, zf=zf)
        bg_kind, bg_val, _bg_scale = resolve_icon_layer(apk_path, full_res, bg_addr, index=index, zf=zf)
        check()
        if fg_kind in ("image", "color", "vector") and bg_kind in ("image", "color", "vector"):
            try:
                return compose_adaptive_icon(
                    apk_path,
                    {"type": fg_kind, "value": fg_val},
                    {"type": bg_kind, "value": bg_val},
                    fg_scale=fg_scale,
                    full_res=full_res,
                    index=index,
                    zf=zf,
                )
            except _Cancelled:
                raise
            except Exception as e:
                # 层解析成功不代表能渲染：回退到下面的位图回退
                logging.warning("合成自适应图标失败，改用位图回退: %s", e)

    # 回退：找 icon xml 所属 mipmap 条目的最高密度位图
    check()
    if full_res is None:
        full_res = run_aapt2_dump_resource(apk_path)
        if full_res is None:
            full_res = ""
        check()
        index = get_resource_index(full_res)
    fallback = find_mipmap_fallback(full_res, icon_path, index)
    if fallback:
        with open_apk_zip(apk_path, zf) as shared_zf:
            with shared_zf.open(fallback) as f:
                img = Image.open(f).convert("RGBA")
        img = img.resize((ICON_SIZE, ICON_SIZE), Image.LANCZOS)
        return img, to_png_bytes(img)
    return None, b""


def extract_icon(apk_path: str, icon_path: str, check_cancel=None, zf=None):
    """执行一次完整图标提取，返回 (QImage, 导出用 PNG 字节)。

    独立于 IconWorker 线程的纯执行逻辑：--self-test 等不涉及 Qt 线程的
    场景直接调用本函数即可，无需为同步跑一次提取而构造未启动的 QThread。
    check_cancel 是可选取消检查回调（过期时抛 _Cancelled）；线程内调用
    时由 IconWorker 传入自己的检查点。
    """
    check = check_cancel or _never_cancelled
    img = QtGui.QImage()
    data = b""
    with open_apk_zip(apk_path, zf) as shared_zf:
        kind = _icon_kind(apk_path, icon_path, shared_zf)
        if kind == "image":
            raw = shared_zf.open(icon_path).read()
            # 只解码一次：显示直接搬运像素，导出复用同一次解码结果归一化。
            # 旧实现先归一化编码成 PNG、再把 PNG 交给 Qt 解码，白多一编一解。
            im, fmt = decode_icon_image(raw)
            if im is not None:
                display, data = normalize_icon_image(raw, im=im, fmt=fmt)
                img = _qimage_from_pil(display)
            elif not _load_image(img, raw):
                # 后缀可能是伪装/错误的：按魔数再确认一次是否为 XML。
                # 例如 AndResGuard 有时会把二进制 XML 改名成 .png。
                if sniff_file_kind(apk_path, icon_path, zf=shared_zf) == "xml":
                    kind = "xml"
                else:
                    raise ValueError(f"图标文件无法解码为图片: {icon_path}")

        if kind == "xml":
            im, data = _adaptive_icon_result(apk_path, icon_path, check, zf=shared_zf)
            if not data:
                raise ValueError("自适应图标的前景/背景均无法渲染，且未找到位图回退图标")
            img = _qimage_from_pil(im) if im is not None else QtGui.QImage()
            if img.isNull():
                raise ValueError("合成后的图标无法解码为图片")
        elif kind != "image":
            raise ValueError(f"无法识别图标类型（非图片也非 XML）: {icon_path}")
    return img, data


class IconWorker(QtCore.QThread):
    """常驻的图标提取工作线程（Worker-Object 门面与生命周期管理）。

    架构特点：
    - 业务逻辑与执行状态封装在 _IconWorkerCore(QObject) 中，通过 moveToThread 移入自身；
    - 线程自身运行标准 Qt 事件循环（默认 exec()），完全移除了底层的 threading.Condition 轮询；
    - 请求派发与结果回传完全通过 Qt 信号槽队列机制，零 CPU 占用挂起；
    - 对外提供稳定的 QThread 线程控制接口（start, stop, wait, isRunning）与向后兼容方法。
    """
    iconReady = QtCore.pyqtSignal(QtGui.QImage, bytes, int)  # 成功（QImage 在槽内转 QPixmap；字节流供导出）
    failed = QtCore.pyqtSignal(str, int)  # 提取失败时发出，供 UI 可见提示

    def __init__(self, parent=None):
        super().__init__(parent)
        self._core = _IconWorkerCore(self)
        self._core.moveToThread(self)
        self._core.iconReady.connect(self.iconReady)
        self._core.failed.connect(self.failed)
        self.finished.connect(self._core.deleteLater)

    # ---------------- UI 线程接口 ----------------
    def request(self, apk_path: str, icon_path: str) -> int:
        """登记一次提取请求（覆盖尚未开始的旧请求），返回本次代数。"""
        return self._core.request(apk_path, icon_path)

    def stop(self):
        """请求工作线程结束（关闭窗口时调用）。"""
        self._core.stop()
        self.requestInterruption()
        self.quit()

    def cancel(self):
        """作废在途/待办的提取任务，并终止图标线程正在跑的 aapt2 dump。

        新一轮解析开始时调用：当前文件已经换掉，上一个 APK 的图标任务
        没有继续的必要。除了推进代数让工作线程在检查点退出，还要结束
        已在运行的 resources/xmltree 子进程——否则旧 APK 的 dump 可能
        继续占用常驻图标线程，新 APK 的图标要排队等到它超时（最坏 60s）。
        """
        self._core.cancel()
        # 只终止图标线程自己的标签：badging 由 MainWindow.process_apk
        # 定向终止，这里不能无差别 kill。
        kill_running_aapt2(tags=("resources", "xmltree"))

    def _is_stale(self, gen: int) -> bool:
        return self._core.is_stale(gen)

    def is_busy(self) -> bool:
        """是否有图标提取在途（重命名前等待文件句柄释放时使用）。"""
        return self._core.is_busy()

    def _check_cancel(self):
        """当前请求已过期（有新请求/窗口关闭）时抛出 _Cancelled。"""
        self._core.check_cancel()

    # 子线程只碰 QImage（回归守护：_load_image 必须在，_load_pixmap 不许回来）
    _load_image = staticmethod(_load_image)

    def _extract_adaptive_icon(self, apk_path: str, icon_path: str, zf=None) -> bytes:
        """向后兼容入口：实现见模块级 _adaptive_icon_result（返回其中的 PNG 字节）。"""
        return _adaptive_icon_result(apk_path, icon_path, self._check_cancel, zf)[1]

    def _extract(self, apk_path: str, icon_path: str, zf=None):
        """向后兼容入口：实现见模块级 extract_icon。"""
        return extract_icon(apk_path, icon_path, check_cancel=self._check_cancel, zf=zf)


class _ApkInfoWorkerCore(QtCore.QObject):
    """在工作线程中实际执行 APK dump badging 的 Worker Object。"""
    resultReady = QtCore.pyqtSignal(str, int)
    failed = QtCore.pyqtSignal(str, int)
    _trigger = QtCore.pyqtSignal()

    def __init__(self, owner, single_shot: bool = False):
        super().__init__()
        self._owner = owner
        self._single_shot = single_shot
        self._lock = threading.Lock()
        self._pending = None      # (apk_path, gen)
        self._gen = 0
        self._current_gen = 0
        self._stopping = False
        self._trigger.connect(self._do_work, QtCore.Qt.ConnectionType.QueuedConnection)

    def request(self, apk_path: str) -> int:
        """登记一次解析请求（覆盖尚未开始的旧请求），返回本次代数。"""
        with self._lock:
            self._gen += 1
            self._pending = (apk_path, self._gen)
            gen = self._gen
        self._trigger.emit()
        return gen

    def stop(self):
        """请求工作线程结束。"""
        with self._lock:
            self._stopping = True
            self._pending = None

    def is_stale(self, gen: int) -> bool:
        with self._lock:
            return self._stopping or gen != self._gen

    @QtCore.pyqtSlot()
    def _do_work(self):
        """由 Qt 事件循环调度的后台执行槽函数。"""
        with self._lock:
            if self._stopping or self._pending is None:
                return
            apk_path, gen = self._pending
            self._pending = None
            self._current_gen = gen

        if self.is_stale(gen) or self._owner.isInterruptionRequested():
            return

        try:
            output = run_aapt2_dump_badging(apk_path)
        except FileNotFoundError as e:
            if not self.is_stale(gen):
                self.failed.emit(str(e), gen)
            self._check_single_shot()
            return
        except Exception as e:
            if not self.is_stale(gen):
                self.failed.emit(f"执行 aapt2 失败：\n{e}", gen)
            self._check_single_shot()
            return

        if not self.is_stale(gen) and not self._owner.isInterruptionRequested():
            self.resultReady.emit(output, gen)

        self._check_single_shot()

    def _check_single_shot(self):
        """单次执行模式下，在任务完成后自动退出事件循环。"""
        if self._single_shot:
            with self._lock:
                if not self._pending:
                    self._owner.quit()


class ApkInfoWorker(QtCore.QThread):
    """后台常驻或单次执行解析工作线程（Worker-Object 门面）。

    采用标准 Qt Worker-Object 模式：
    - 业务逻辑封装在 _ApkInfoWorkerCore(QObject) 中并移入线程；
    - 支持常驻长连接（单线程最新覆盖）与单次运行自动退出两种模式；
    - 彻底告别轮询，由 Qt 事件循环响应任务。
    """
    resultReady = QtCore.pyqtSignal(str, int)
    failed = QtCore.pyqtSignal(str, int)

    def __init__(self, apk_path: str = None, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path
        self._core = _ApkInfoWorkerCore(self, single_shot=bool(apk_path))
        self._core.moveToThread(self)
        self._core.resultReady.connect(self.resultReady)
        self._core.failed.connect(self.failed)
        self.finished.connect(self._core.deleteLater)
        if apk_path:
            self.request(apk_path)

    def request(self, apk_path: str) -> int:
        """登记一次解析请求（覆盖尚未开始的旧请求），返回本次代数。"""
        return self._core.request(apk_path)

    def stop(self):
        """请求工作线程结束。"""
        self._core.stop()
        self.requestInterruption()
        self.quit()

    def _is_stale(self, gen: int) -> bool:
        return self._core.is_stale(gen)
