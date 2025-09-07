# -*- coding: utf-8 -*-
import os
import sys
import re
import shlex
import shutil
import subprocess
import json
from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets


def load_sdk_versions():
    """尝试读取同级目录下 android_sdk_versions.json"""
    sdk_map = {}
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    sdk_file = here / "android_sdk_versions.json"
    if not sdk_file.exists():
        return
    try:
        with open(sdk_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 建立 {apiLevel: (版本, codename)} 映射
        for item in data:
            api = str(item.get("apiLevel"))
            version = item.get("version", "")
            codename = item.get("codename") or ""
            # 去掉"Android "前缀
            if version.startswith("Android "):
                version = version.replace("Android ", "", 1)
            # codename 去空格
            codename = codename.replace(" ", "") if codename else ""
            # 拼接成 "8.0 Pie" 或 "14 UpsideDownCake"
            if codename:
                sdk_map[api] = f"{version} {codename}"
            else:
                sdk_map[api] = version
        return sdk_map
    except Exception as e:
        print("读取 android_sdk_versions.json 出错:", e)

def find_aapt2() -> str:
    """
    优先在脚本同级目录查找 aapt2 / aapt2.exe；否则使用系统 PATH 中的 aapt2。
    找不到则抛出 FileNotFoundError。
    """
    here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # 支持 PyInstaller
    candidates = [here / "aapt2", here / "aapt2.exe"]
    for c in candidates:
        if c.exists() and os.access(str(c), os.X_OK):
            return str(c)

    sys_aapt2 = shutil.which("aapt2")
    if sys_aapt2:
        return sys_aapt2

    raise FileNotFoundError("未找到 aapt2，请将 aapt2 放到脚本同级目录或加入系统 PATH。")


def run_aapt2_dump_badging(apk_path: str) -> str:
    """
    运行 `aapt2 dump badging "<apk>"` 并返回 stdout 文本。
    """
    aapt2_path = find_aapt2()
    cmd = [aapt2_path, "dump", "badging", apk_path]

    # Windows 控制台编码兼容：优先 utf-8，失败再回退到 gbk
    try:
        out = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
    except subprocess.CalledProcessError as e:
        # 即使非0，也尽量取输出
        out = e

    data = out.stdout or out.stderr
    text = None
    for enc in ("utf-8", "utf-8-sig", "gbk", "cp936"):
        try:
            text = data.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    if text is None:
        text = data.decode(errors="ignore")
    return text


def parse_aapt2_output(text: str) -> dict:
    """
    解析 aapt2 dump badging 输出，返回结构化信息。
    优先中文应用名：zh-CN -> zh-HK -> zh-TW -> 通用 application-label -> application: label
    """
    info = {
        "package_name": "",
        "version_name": "",
        "version_code": "",
        "platform_build_version_name": "",
        "platform_build_version_code": "",
        "compile_sdk_version": "",
        "compile_sdk_codename": "",
        "min_sdk": "",
        "target_sdk": "",
        "app_name": "",
        "app_name_labels": {},  # locale -> label
        "launchable_activity": "",
        "permissions": [],
        "features": [],
        "implied_features": [],
        "supports_screens": [],
        "supports_any_density": "",
        "densities": [],
        "locales": [],
        "icons": {},  # density -> path
        "raw": text.strip(),
        "architectures": [],   # 新增：支持架构
    }

    # --- 基本信息 ---
    m_pkg = re.search(
        r"package:\s+name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']+)'.*?",
        text,
        re.S,
    )
    if m_pkg:
        info["package_name"] = m_pkg.group(1)
        info["version_code"] = m_pkg.group(2)
        info["version_name"] = m_pkg.group(3)

    # 平台/编译 SDK
    m_plat = re.search(
        r"platformBuildVersionName='([^']+)'", text
    )
    if m_plat:
        info["platform_build_version_name"] = m_plat.group(1)

    m_platc = re.search(
        r"platformBuildVersionCode='([^']+)'", text
    )
    if m_platc:
        info["platform_build_version_code"] = m_platc.group(1)

    m_compile = re.search(r"compileSdkVersion='([^']+)'", text)
    if m_compile:
        info["compile_sdk_version"] = m_compile.group(1)

    m_compile_code = re.search(r"compileSdkVersionCodename='([^']+)'", text)
    if m_compile_code:
        info["compile_sdk_codename"] = m_compile_code.group(1)

    # Sdk 版本
    m_min = re.search(r"minSdkVersion:'([^']+)'", text)
    if m_min:
        info["min_sdk"] = m_min.group(1)
    m_target = re.search(r"targetSdkVersion:'([^']+)'", text)
    if m_target:
        info["target_sdk"] = m_target.group(1)

    # --- 应用名（多语言） ---
    for loc, label in re.findall(r"application-label-([\w-]+):'([^']*)'", text):
        info["app_name_labels"][loc] = label

    # 通用标签
    m_label_generic = re.search(r"application-label:'([^']*)'", text)
    generic_label = m_label_generic.group(1) if m_label_generic else ""

    # application 节点的 label
    m_label_app = re.search(r"application:\s+label='([^']*)'", text)
    app_node_label = m_label_app.group(1) if m_label_app else ""

    # 选择优先中文
    for pref in ("zh-CN", "zh-HK", "zh-TW"):
        if info["app_name_labels"].get(pref):
            info["app_name"] = info["app_name_labels"][pref]
            break
    if not info["app_name"]:
        info["app_name"] = (
            generic_label
            or info["app_name_labels"].get("zh", "")
            or app_node_label
        )

    # --- 可启动 Activity ---
    m_launch = re.search(
        r"launchable-activity:\s+name='([^']*)'(?:\s+label='([^']*)')?", text
    )
    if m_launch:
        info["launchable_activity"] = m_launch.group(1)

    # --- 权限 ---
    info["permissions"] = [p for p in re.findall(r"uses-permission:\s+name='([^']+)'", text)]

    # --- Feature ---
    info["features"] = [f for f in re.findall(r"uses-feature:\s+name='([^']+)'", text)]
    info["implied_features"] = [
        f for f in re.findall(r"uses-implied-feature:\s+name='([^']+)'", text)
    ]

    # --- 支持屏幕/密度/语言 ---
    m_screens = re.search(r"supports-screens:\s+((?:'[^']+'\s*)+)", text)
    if m_screens:
        info["supports_screens"] = re.findall(r"'([^']+)'", m_screens.group(1))

    m_anyden = re.search(r"supports-any-density:\s+'([^']+)'", text)
    if m_anyden:
        info["supports_any_density"] = m_anyden.group(1)

    m_dens = re.search(r"densities:\s+((?:'[^']+'\s*)+)", text)
    if m_dens:
        info["densities"] = re.findall(r"'([^']+)'", m_dens.group(1))

    m_loc = re.search(r"locales:\s+((?:'[^']+'\s*)+)", text)
    if m_loc:
        info["locales"] = re.findall(r"'([^']+)'", m_loc.group(1))

    # --- 图标（按密度） ---
    for dens, path_ in re.findall(r"application-icon-([0-9]+):'([^']+)'", text):
        info["icons"][dens] = path_

    # --- 支持架构 ---
    archs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("native-code:") or line.startswith("alt-native-code:"):
            found = re.findall(r"'([^']+)'", line)
            archs.extend(found)
    info["architectures"] = archs

    return info


class DropLineEdit(QtWidgets.QLineEdit):
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
        for url in e.mimeData().urls():
            local = url.toLocalFile()
            if local.lower().endswith(".apk"):
                self.setText(local)
                self.fileDropped.emit(local)
                break


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("APK 信息查看器（aapt2）")
        self.resize(1050, 700)
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # 顶部：文件选择/拖放
        file_row = QtWidgets.QHBoxLayout()
        self.apk_path_edit = DropLineEdit()
        self.apk_path_edit.fileDropped.connect(self.process_apk)
        btn_browse = QtWidgets.QPushButton("打开 APK")
        btn_browse.clicked.connect(self.browse_apk)
        file_row.addWidget(self.apk_path_edit, stretch=1)
        file_row.addWidget(btn_browse)
        layout.addLayout(file_row)

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

        # 原始输出
        raw_group = QtWidgets.QGroupBox("aapt2 原始输出")
        vg = QtWidgets.QVBoxLayout(raw_group)
        self.te_raw = QtWidgets.QPlainTextEdit()
        self.te_raw.setReadOnly(True)
        self.te_raw.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        vg.addWidget(self.te_raw)
        layout.addWidget(raw_group, stretch=1)

        # 底部按钮
        btn_row = QtWidgets.QHBoxLayout()
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
        te.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        layout.addWidget(te)
        return {"group": group, "edit": te}

    def browse_apk(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "选择 APK 文件", "", "APK 文件 (*.apk)"
        )
        if path:
            self.apk_path_edit.setText(path)
            self.process_apk(path)

    def process_apk(self, path: str):
        if not path or not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(self, "提示", "请选择有效的 APK 文件。")
            return
        try:
            output = run_aapt2_dump_badging(path)
        except FileNotFoundError as e:
            QtWidgets.QMessageBox.critical(self, "错误", str(e))
            return
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "错误", f"执行 aapt2 失败：\n{e}")
            return

        self.te_raw.setPlainText(output)
        info = parse_aapt2_output(output)
        self.fill_info(info)

    def reparse_current(self):
        text = self.te_raw.toPlainText()
        if not text.strip():
            return
        info = parse_aapt2_output(text)
        self.fill_info(info)

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

        summary = "\n".join(lines)
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(summary)
        QtWidgets.QMessageBox.information(self, "已复制", "已复制摘要到剪贴板。")


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet("QLabel { font-size: 16px; font-family: Microsoft Yahei; }" \
    "QGroupBox { font-size: 16px; font-family: Microsoft Yahei; }")
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
