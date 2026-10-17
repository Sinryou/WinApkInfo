# -*- coding: utf-8 -*-
"""后台解析工作线程（ApkInfoWorker、IconWorker）。"""
import io
import time
import zipfile
import threading
import logging
import re
from PIL import Image
from PyQt6 import QtCore, QtGui

from core.aapt import run_aapt2_dump_badging, run_aapt2_dump_resource, run_aapt2_dump_xmltree
from core.resources import _ResourceIndex, _open_apk_zip
from core.vector import rasterize_vector_layer
from core.apk_parser import (
    _ICON_SIZE, find_adaptive_layer_addr, resolve_icon_layer,
    extract_icon_bytes, find_mipmap_fallback, _normalize_icon_png
)

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

    def _extract_adaptive_icon(self, apk_path: str, icon_path: str, zf=None) -> bytes:
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
            fg_kind, fg_val, fg_scale = resolve_icon_layer(apk_path, full_res, fg_addr, index=index, zf=zf)
            bg_kind, bg_val, _bg_scale = resolve_icon_layer(apk_path, full_res, bg_addr, index=index, zf=zf)
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
                        zf=zf,
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
            with _open_apk_zip(apk_path, zf) as shared_zf:
                img = Image.open(shared_zf.open(fallback)).convert("RGBA")
            img = img.resize((_ICON_SIZE, _ICON_SIZE), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        return b""

    def _extract(self, apk_path: str, icon_path: str, zf=None):
        """执行一次提取，返回 (QImage, 导出用 PNG 字节)。"""
        img = QtGui.QImage()
        data = b""
        with _open_apk_zip(apk_path, zf) as shared_zf:
            if icon_path.lower().endswith(('.png', '.jpg', '.jpeg', '.webp', '.gif')):
                raw = shared_zf.open(icon_path).read()
                # 与自适应/矢量链路统一导出规格（_ICON_SIZE²）；PIL 解不了时
                # 保留原始字节，交给 Qt 解码器兜底。
                data = _normalize_icon_png(raw) or raw
                if not self._load_image(img, data):
                    raise ValueError(f"图标文件无法解码为图片: {icon_path}")

            elif icon_path.lower().endswith('.xml'):
                data = self._extract_adaptive_icon(apk_path, icon_path, zf=shared_zf)
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

