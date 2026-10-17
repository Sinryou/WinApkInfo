# -*- coding: utf-8 -*-
"""主界面窗口与全局异常捕获。"""
import os
import sys
import time
import logging
import functools
from pathlib import Path
from PyQt6 import QtCore, QtGui, QtWidgets

from version import __version__
from core.aapt import kill_running_aapt2, get_disk_cache_info, clear_disk_cache
from core.resources import local_resource_path, load_sdk_versions
from core.apk_parser import _sanitize_apk_name, parse_aapt2_output
from ui.workers import IconWorker, ApkInfoWorker
from ui.widgets import DropLineEdit

# 关闭窗口时等待后台线程收尾的时间（毫秒）
_CLOSE_WAIT_MS = 2000

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("APK 信息查看器（aapt2）")
        self.setWindowIcon(QtGui.QIcon(local_resource_path("resources/logo.ico")))
        self.resize(700, 700)
        self._busy = False
        # 当前已解析 APK 的路径：process_apk 显式记录，不再靠回读输入框
        self._apk_path = ""
        # 最近一次成功解析的 badging 原始输出与对应文件路径。
        # “重新解析”和“执行重命名”都以这里为准，不再依赖隐藏控件，
        # 避免解析失败后残留的占位文本被当成真实输出。
        self._raw_output = ""
        self._parse_ok_path = ""
        # 基础解析线程（单常驻线程 + 最新请求覆盖）与向后兼容引用列表
        self._apk_worker = None
        self._apk_gen = 0
        self._apk_workers = []
        # 图标提取是常驻线程（单线程 + 最新请求覆盖），首次使用时创建
        self._icon_worker = None
        self._icon_gen = 0  # 最近一次图标请求的代数，用于丢弃延迟投递的旧结果
        self.setup_ui()

    def setup_ui(self):
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

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

        # 底部按钮
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_about = QtWidgets.QPushButton(" 关于 ")
        self.btn_about.setIcon(QtGui.QIcon(local_resource_path("resources/info.png")))
        self.btn_about.clicked.connect(self.show_about)
        btn_row.addWidget(self.btn_about)
        self.btn_clear_cache = QtWidgets.QPushButton("清理缓存")
        self.btn_clear_cache.clicked.connect(self.clear_cache)
        btn_row.addWidget(self.btn_clear_cache)
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
        self._apk_path = path
        # 开始新一轮解析前清空上一轮的可导出/可重命名状态：
        # 否则新 APK 解析失败时，旧图标和旧文件名预览会被误认为属于新文件。
        self._raw_output = ""
        self._parse_ok_path = ""
        self._current_icon_bytes = None
        self.icon_label.clear()
        self.btn_export_icon.setVisible(False)
        self.lbl_icon_hint.clear()
        self.lbl_icon_hint.setToolTip("")
        self.rename_preview.clear()
        # 若已有任务正在解析，强制中断前序 aapt2 子进程以快速让路，不再弹模态弹窗打断用户
        if self._busy:
            kill_running_aapt2()
        try:
            self.set_busy(True)
            self._start_apk_worker(path)
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
            self.statusBar().showMessage("正在解析 APK，请稍候…")
        else:
            self.unsetCursor()
            self.statusBar().clearMessage()

    def _start_apk_worker(self, apk_path: str):
        """把 APK 解析请求交给常驻线程，最新请求覆盖旧请求。"""
        if self._apk_worker is None:
            self._apk_worker = ApkInfoWorker()
            self._apk_worker.resultReady.connect(self.on_apk_info_ready)
            self._apk_worker.failed.connect(self.on_apk_info_failed)
            self._apk_workers = [self._apk_worker]
            self._apk_worker.start()
        self._apk_gen = self._apk_worker.request(apk_path)

    def _stop_apk_worker(self):
        """请求常驻解析线程结束（关闭窗口/退出时调用）。"""
        if self._apk_worker is not None:
            self._apk_worker.stop()

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
        self._stop_apk_worker()
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

    def shutdown_background(self, timeout_ms: int = 5000) -> bool:
        """退出前等待后台线程真正结束。

        QThread 在运行中被析构会让进程崩溃，因此事件循环结束后仍要确认。
        返回是否全部结束。
        """
        self._stop_icon_worker()
        self._stop_apk_worker()
        kill_running_aapt2()
        all_done = True
        for t in self._apk_workers + ([self._icon_worker] if self._icon_worker else []):
            if t.isRunning() and not t.wait(timeout_ms):
                logging.warning("后台线程仍在运行，等待超时: %s", t)
                all_done = False
        return all_done

    def on_apk_info_ready(self, output: str, gen: int = 0):
        if gen != 0 and gen != self._apk_gen:
            return  # 延迟到达的旧请求结果，丢弃
        try:
            # 先记录原始输出：解析成功与否都不影响后续“重新解析”使用真实文本
            self._raw_output = output
            self._parse_ok_path = self._apk_path
            info = parse_aapt2_output(output)
            self.fill_info(info)
        except Exception as e:
            # slot 内未捕获异常会让 PyQt6 直接 qFatal() 结束进程，必须自行兜住
            logging.exception("处理 aapt2 输出失败: %s", e)
            QtWidgets.QMessageBox.critical(self, "错误", f"解析 APK 信息失败：\n{e}")
        finally:
            # 无论成功失败都要恢复界面，否则按钮会永久禁用
            self.set_busy(False)

    def on_apk_info_failed(self, message: str, gen: int = 0):
        if gen != 0 and gen != self._apk_gen:
            return
        logging.warning("解析 APK 失败（%s）：%s", self._apk_path, message)
        # 失败后必须清空本轮状态：否则“重新解析”会把占位文本当 badging，
        # 重命名预览也会把上一个 APK 的名字用到当前文件上。
        self._raw_output = ""
        self._apk_path = ""
        self._parse_ok_path = ""
        self._current_icon_bytes = None
        self.icon_label.clear()
        self.btn_export_icon.setVisible(False)
        self.lbl_icon_hint.clear()
        self.lbl_icon_hint.setToolTip("")
        self.rename_preview.clear()
        QtWidgets.QMessageBox.critical(self, "错误", message)
        self.set_busy(False)

    def reparse_current(self):
        # 只重新解析最近一次成功得到的真实 badging 文本；
        # 解析失败后 _raw_output 已清空，不能再用隐藏控件里的占位内容。
        if not self._raw_output.strip():
            return
        try:
            info = parse_aapt2_output(self._raw_output)
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

        # 提取图标：先无条件清空上一轮的图标/提示。新 APK 没有图标时，
        # 旧的 pixmap、导出字节和上次的失败提示都不能继续留在界面上。
        self.icon_label.clear()
        self.lbl_icon_hint.clear()
        self.lbl_icon_hint.setToolTip("")
        self._current_icon_bytes = None
        self.btn_export_icon.setVisible(False)

        apk_path = self._current_apk_path()
        if not icons:
            self.lbl_icon_hint.setText("未找到可用图标")
            self.lbl_icon_hint.setToolTip(
                "该 APK 的 badging 输出中没有 application-icon 或 application icon 条目"
            )
        elif apk_path and os.path.isfile(apk_path):
            try:
                # 选择最大 density 的 icon（adaptive icon 的 anydpi XML 会排在最高位）
                best = max(icons.items(), key=lambda x: int(x[0]))
                self._start_icon_worker(apk_path, best[1])
            except Exception as e:
                logging.exception("提取图标失败: %s", e)
        else:
            self.lbl_icon_hint.setText("未找到可读取的 APK 文件")

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
        if self._parse_ok_path != old_path:
            # 解析失败或输入框被改成别的路径时，预览名仍可能来自上一个 APK，
            # 直接重命名会把错误的名字用到当前文件上。
            QtWidgets.QMessageBox.warning(
                self, "提示", "当前 APK 尚未成功解析，请先重新解析后再重命名。"
            )
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
            self._parse_ok_path = new_path
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

    def clear_cache(self):
        """清理本地磁盘 aapt2 输出缓存。"""
        info = get_disk_cache_info()
        count = info.get("count", 0)
        mb = info.get("total_mb", 0.0)
        ret = QtWidgets.QMessageBox.question(
            self,
            "清理缓存确认",
            f"当前磁盘缓存共 {count} 条，占用约 {mb} MB。\n\n"
            "清理缓存将删除所有本地 aapt2 dump 磁盘条目与内存缓存。\n是否继续？",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        if ret == QtWidgets.QMessageBox.StandardButton.Yes:
            freed = clear_disk_cache()
            QtWidgets.QMessageBox.information(
                self, "完成", f"已清空磁盘与内存缓存，共释放 {freed / (1024 * 1024):.2f} MB 空间。"
            )

    def show_about(self):
        info = get_disk_cache_info()
        cache_line = f"当前磁盘缓存: {info.get('count', 0)} 条 / {info.get('total_mb', 0.0)} MB<br>"
        QtWidgets.QMessageBox.about(
            self,
            "About",
            "<b>APK 信息查看器</b><br><br>"
            "基于 PyQt6 + aapt2 的图形化<br>"
            "解析 APK 文件信息的工具程序<br><br>"
            f"{cache_line}<br>"
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

