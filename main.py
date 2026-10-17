# -*- coding: utf-8 -*-
"""WinApkInfo - 基于 PyQt6 + aapt2 的图形化 APK 信息查看与自适应图标提取工具。

本项目已按职责解耦为以下子模块：
  - core.aapt: aapt2 进程调度、超时处理、输出解码与多级缓存；
  - core.colors: Android 框架预设颜色表与颜色解析；
  - core.resources: 资源索引表、AXML 解析、SDK 版本映射与文件探测；
  - core.vector: Android VectorDrawable 矢量图形解析与光栅化渲染引擎；
  - core.apk_parser: 自适应图标图层定位、合成、badging 信息结构化提取与文件名净化；
  - ui.workers: 后台解析工作线程（ApkInfoWorker、IconWorker）；
  - ui.widgets: 自定义 UI 控件（DropLineEdit）；
  - ui.main_window: 主窗口（MainWindow）与全局异常捕获钩子。

本入口模块同时向后兼容导出所有核心符号，供测试套件与打包脚本无缝调用。
"""
import os
import sys
import subprocess
import tempfile
import logging
from pathlib import Path

from version import __version__

try:
    import numpy as np
except ImportError:
    np = None

from PyQt6 import QtCore, QtGui, QtWidgets

# 核心模块导入
import core.aapt as _aapt_mod
import core.colors as _colors_mod
import core.resources as _resources_mod
import core.vector as _vector_mod
import core.apk_parser as _apk_parser_mod
import ui.workers as _workers_mod
import ui.widgets as _widgets_mod
import ui.main_window as _main_window_mod

# 导出 core.aapt 符号
from core.aapt import (
    _SUBPROCESS_FLAGS,
    Aapt2Error,
    _AAPT2_TIMEOUT,
    _running_procs,
    _running_procs_lock,
    _run_aapt2,
    kill_running_aapt2,
    _decode_output,
    _Aapt2OutputCache,
    _default_disk_cache_dir,
    _aapt2_cache_key,
    _aapt2_cache,
    find_aapt2,
    run_aapt2_dump_badging,
    run_aapt2_dump_resource,
    run_aapt2_dump_xmltree,
)

# 导出 core.colors 符号
from core.colors import (
    parse_android_color,
    _FRAMEWORK_COLOR_MAP,
)

# 导出 core.resources 符号
from core.resources import (
    local_resource_path,
    _sdk_load_warned,
    load_sdk_versions,
    _LazyEntryMap,
    _entry_span,
    _ResourceIndex,
    extract_resource_entry,
    _density_of,
    _pick_best_density,
    _sniff_cache,
    _sniff_cache_lock,
    _sniff_file_kind,
    _BITMAP_EXTS,
    _DPI_ORDER,
    _MAX_DEREF_DEPTH,
    get_resource_info,
    _open_apk_zip,
)

# 导出 core.vector 符号
from core.vector import (
    _VECTOR_CAPS,
    _parse_vector_elements,
    _attr_float,
    _attr_enum,
    _attr_int,
    _tokenize_path_data,
    _parse_path_commands,
    _bezier_points,
    _quad_points,
    _arc_points,
    _flatten_subpaths,
    _mat_mul,
    _mat_apply,
    _mat_scale,
    _group_matrix,
    _MASK_CHUNK_ROWS,
    _collect_edges,
    _fill_mask_py,
    _build_fill_mask,
    _parse_gradient,
    _sample_gradient_stops,
    _sample_gradient_stops_vec,
    _render_gradient,
    _render_gradient_py,
    _resolve_vector_fill,
    _extend_square_caps,
    _draw_stroke,
    _cmds_to_qpainterpath,
    rasterize_vector_layer,
    _trim_to_content,
)

# 导出 core.apk_parser 符号
from core.apk_parser import (
    _ICON_SIZE,
    _RESERVED_NAMES,
    find_adaptive_layer_addr,
    _resolve_xml_wrapper,
    resolve_icon_layer,
    _collect_bitmap_variants,
    find_mipmap_fallback,
    load_resource,
    _normalize_icon_png,
    _place_by_gravity,
    extract_icon_bytes,
    parse_aapt2_output,
    _sanitize_apk_name,
)

# 导出 ui.workers 符号
from ui.workers import (
    _Cancelled,
    IconWorker,
    ApkInfoWorker,
)

# 导出 ui.widgets 符号
from ui.widgets import (
    DropLineEdit,
)

# 导出 ui.main_window 符号
from ui.main_window import (
    _CLOSE_WAIT_MS,
    MainWindow,
    _ErrorDialog,
    _on_gui_thread,
    install_excepthook,
)


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


def _default_log_dir() -> str:
    """返回标准日志目录（优先 %LOCALAPPDATA%/WinApkInfo）。"""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return os.path.join(local_app_data, "WinApkInfo")

    try:
        from PyQt6.QtCore import QStandardPaths
        base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
        if base:
            return os.path.join(base, "WinApkInfo") if "winapkinfo" not in base.lower() else base
    except Exception:
        pass

    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".local", "state")):
        return os.path.join(home, ".local", "state", "WinApkInfo")

    return tempfile.gettempdir()


def _default_log_path() -> str:
    """返回日志文件的绝对路径（%LOCALAPPDATA%/WinApkInfo/winapkinfo.log），确保父目录存在。"""
    log_dir = _default_log_dir()
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        log_dir = tempfile.gettempdir()
    return os.path.join(log_dir, "winapkinfo.log")


def main():
    # 日志：控制台模式输出到 stderr，同时统一落盘到标准日志路径 %LOCALAPPDATA%/WinApkInfo/winapkinfo.log
    log_path = _default_log_path()
    handlers = []
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))
    try:
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    except OSError:
        pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers if handlers else None,
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


def __getattr__(name: str):
    """向后兼容属性动态读取（PEP 562）。"""
    if name == "_error_dialog":
        return _main_window_mod._error_dialog
    if name == "_sdk_versions_cache":
        return _resources_mod._sdk_versions_cache
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


if __name__ == "__main__":
    sys.exit(main())
