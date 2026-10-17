# -*- coding: utf-8 -*-
"""WinApkInfo 核心逻辑包。

各子模块按需导入（例如 ``import core.aapt``）。这里刻意不做聚合导入：
否则任何 ``core.*`` 导入都会连带加载 PyQt6 / numpy / Pillow 等重依赖，
既拖慢启动，也会让按值导入的可变全局（如 SDK 缓存）产生陈旧副本。
需要兼容导出的调用方请使用 ``main`` 模块。
"""
