# -*- coding: utf-8 -*-
"""WinApkInfo - 基于 PyQt6 + aapt2 的图形化 APK 信息查看与自适应图标提取工具。

本项目已按职责解耦为以下子模块：
  - core.aapt: aapt2 进程调度、超时处理、输出解码与多级缓存；
  - core.colors: Android 框架预设颜色表与颜色解析；
  - core.paths: 日志/磁盘缓存等标准应用目录解析；
  - core.resources: 资源索引表、AXML 解析、SDK 版本映射与文件探测；
  - core.vector: Android VectorDrawable 矢量图形解析与光栅化渲染引擎；
  - core.apk_parser: 自适应图标图层定位、合成、badging 信息结构化提取与文件名净化；
  - ui.workers: 后台解析工作线程（ApkInfoWorker、IconWorker）；
  - ui.widgets: 自定义 UI 控件（DropLineEdit）；
  - ui.main_window: 主窗口（MainWindow）与全局异常捕获钩子。

"""
import argparse
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import tempfile

from PyQt6 import QtWidgets

from core.aapt import aapt2_version, find_aapt2, run_aapt2_dump_badging
from core.apk_parser import parse_aapt2_output, pick_best_icon
from core.paths import default_log_dir
from core.resources import load_sdk_versions, local_resource_path
from ui.main_window import MainWindow, install_excepthook
from ui.workers import extract_icon
from version import __version__


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
        aapt2_version()
    except FileNotFoundError as e:
        problems.append(f"找不到可用的 aapt2：{e}")
    except Exception as e:
        problems.append(str(e))

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
            icon_path = pick_best_icon(info.get("icons") or {})
            if not icon_path:
                problems.append(f"样本 APK 没有可用图标：{apk_path}")
            else:
                image, data = extract_icon(apk_path, icon_path)
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


def _default_log_path() -> str:
    """返回日志文件的绝对路径（%LOCALAPPDATA%/WinApkInfo/winapkinfo.log），确保父目录存在。"""
    log_dir = default_log_dir()
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        log_dir = tempfile.gettempdir()
    return os.path.join(log_dir, "winapkinfo.log")


def _parse_args(argv=None):
    """命令行入口定义：--version / --self-test [apk] / 可选的 APK 位置参数。

    用 parse_known_args 忽略多余参数：把 APK 拖到 exe 图标上会以该路径为
    位置参数启动进程，严格 parse_args 会报"unrecognized arguments"并以
    退出码 2 结束，窗口模式（console=False）下表现为程序"双击不启动"。
    """
    parser = argparse.ArgumentParser(
        prog="WinApkInfo",
        description="基于 PyQt6 + aapt2 的图形化 APK 信息查看与图标提取工具。",
    )
    parser.add_argument("--version", action="store_true", help="打印版本号后退出")
    parser.add_argument(
        "--self-test", nargs="?", const="", default=None, metavar="APK",
        help="打包自检：检查 aapt2 与随包资源；附带样本 APK 时完整验证图标提取链路",
    )
    parser.add_argument(
        "apk", nargs="?", default="",
        help="启动后立即解析的 APK 文件（等价于把文件拖到程序图标上）",
    )
    args, _ = parser.parse_known_args(argv)
    return args


def main():
    # 日志：控制台模式输出到 stderr，同时统一落盘到标准日志路径 %LOCALAPPDATA%/WinApkInfo/winapkinfo.log
    log_path = _default_log_path()
    handlers = []
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))
    try:
        handlers.append(
            RotatingFileHandler(
                log_path, maxBytes=2 * 1024 * 1024, backupCount=2, encoding="utf-8"
            )
        )
    except OSError:
        pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers if handlers else None,
    )

    # 构建/排障入口：--version 输出版本，--self-test 检查打包产物是否完整
    args = _parse_args()
    if args.version:
        if sys.stdout is not None:
            print(__version__)
        return 0
    if args.self_test is not None:
        return _self_test(args.self_test or None)

    # 高分屏适配：Qt6 默认启用 high-DPI 缩放（AA_EnableHighDpiScaling /
    # AA_UseHighDpiPixmaps 已废弃），无需再设置任何属性。

    app = QtWidgets.QApplication(sys.argv)
    # 必须在 QApplication 之后：钩子要用主线程创建的提示器做跨线程投递
    install_excepthook()
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    # 命令行/拖放启动时带上了 APK 路径：窗口就绪后立即进入解析流程
    if args.apk:
        w.process_apk(args.apk)
    code = app.exec()
    # 事件循环结束后必须确认后台线程已退出：QThread 运行中被析构会让进程崩溃
    w.shutdown_background()
    return code


if __name__ == "__main__":
    sys.exit(main())
