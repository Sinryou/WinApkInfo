# -*- coding: utf-8 -*-
"""自定义 UI 交互组件。"""
from PyQt6 import QtCore, QtGui, QtWidgets


class DropLineEdit(QtWidgets.QLineEdit):
    """支持拖拽 APK 文件输入的文本框。"""
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
