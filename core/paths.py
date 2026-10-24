# -*- coding: utf-8 -*-
"""跨平台标准应用目录解析：日志目录与 aapt2 磁盘缓存目录共用。

优先级统一为：Windows %LOCALAPPDATA% → Qt 标准位置 → 平台约定
（XDG/home）→ 系统临时目录兜底。不顶层导入 PyQt6，保持 core 模块
在无 Qt 环境下也可用。
"""
import os
import tempfile


def _qt_location(name: str) -> str:
    """按名字解析 QStandardPaths 标准位置；PyQt6 不可用或失败返回空串。"""
    try:
        from PyQt6.QtCore import QStandardPaths
        loc = getattr(QStandardPaths.StandardLocation, name, None)
        if loc is None:
            return ""
        return QStandardPaths.writableLocation(loc) or ""
    except Exception:
        return ""


def _app_dir(qt_base: str, *segments: str) -> str:
    """应用专属目录：LOCALAPPDATA 与 Qt 标准位置两级探测。

    segments 是追加在应用根目录（%LOCALAPPDATA%/WinApkInfo）下的用途
    子目录；Qt 路径已指向 WinApkInfo 目录时直接使用（不再追加），否则
    统一追加 WinApkInfo/<segments>。两级都不可用返回空串，由调用方
    继续走平台约定的回退。
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return os.path.join(local_app_data, "WinApkInfo", *segments)
    if qt_base:
        if "winapkinfo" in qt_base.lower():
            return qt_base
        return os.path.join(qt_base, "WinApkInfo", *segments)
    return ""


def default_log_dir() -> str:
    """标准日志目录：优先 %LOCALAPPDATA%/WinApkInfo。"""
    d = _app_dir(_qt_location("AppLocalDataLocation"))
    if d:
        return d

    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".local", "state")):
        return os.path.join(home, ".local", "state", "WinApkInfo")

    return tempfile.gettempdir()


def default_cache_dir() -> str:
    """标准磁盘缓存目录：优先 %LOCALAPPDATA%/WinApkInfo/cache。

    避免写入系统临时目录后被 Windows 磁盘清理/存储感知程序频繁误删。
    """
    d = _app_dir(_qt_location("CacheLocation"), "cache")
    if d:
        return d

    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        return os.path.join(xdg_cache, "WinApkInfo")

    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".cache")):
        return os.path.join(home, ".cache", "WinApkInfo")

    return os.path.join(tempfile.gettempdir(), "winapk_info_cache")
