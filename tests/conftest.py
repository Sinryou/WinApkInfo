# -*- coding: utf-8 -*-
"""pytest 全局配置：在导入任何 Qt 模块之前完成环境准备。

- QT_QPA_PLATFORM=offscreen：CI/无桌面环境下也能创建 QApplication；
- 把仓库根目录加入 sys.path，保证 core./ui. 包可被导入。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
