# -*- coding: utf-8 -*-
"""WinApkInfo 测试集（pytest 单轨入口）。

包含三类用例：
  - 合成用例（无需样本）：签名/哈希、缓存、资源索引、矢量光栅化、图标嗅探、渐变渲染；
  - 回归检查（tests/regression_checks.py 的 check_*）：线程模型、缓存上限、
    图标提取链路等历史修复的行为守护；
  - 端到端用例（marker: e2e）：需要 testSample/ 真实样本，构建默认不运行。

用法：
    python -m pytest tests -q -m "not e2e"   # 不依赖 testSample，适合 CI
    python -m pytest tests -q                # 含端到端（需 testSample/）
"""
import glob
import io
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import pytest

# 确保项目根目录在 sys.path（直接执行本文件时 conftest 尚未加载）
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from PyQt6 import QtWidgets
import core.aapt as aapt_mod
import core.apk_parser as apk_parser_mod
import core.signature as sig_mod
import core.resources as res_mod
import core.vector as vec_mod
import ui.workers as workers_mod
from PIL import Image
from tests import regression_checks
from ui.workers import IconWorker
from ui.main_window import MainWindow


# 会话级 QApplication 引用：fixture 返回后仍需保活，避免测试中途被回收
_APP = None


@pytest.fixture(scope="session")
def app():
    """会话级 QApplication；同时把模态弹窗替换为记录器，避免无人值守时阻塞。"""
    global _APP
    _APP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    regression_checks.silence_dialogs()
    return _APP


def _signing_block_apk_bytes(pair_len: int) -> bytes:
    """构造只含一个畸形 pair 的最小 APK Signing Block 假 APK（无真实签名）。

    布局遵循 APK Signature Scheme v2：块 = [size(8)][pairs][size(8)][magic(16)]，
    size 值 = pairs 总长 + 24；cd_offset 指向块尾 24 字节（size+magic）的起始，
    使 extract_apk_signatures 的块探测能成功进入 pair 解析循环。
    """
    pairs = struct.pack("<QI", pair_len, 0x7109871A)
    block_size = len(pairs) + 24
    block = (struct.pack("<Q", block_size) + pairs
             + struct.pack("<Q", block_size) + b"APK Sig Block 42")
    eocd = bytearray(22)
    eocd[0:4] = b"PK\x05\x06"
    struct.pack_into("<I", eocd, 16, len(block))  # cd_offset
    return block + bytes(eocd)


class TestSignatureAndMeta(unittest.TestCase):
    """测试 APK 签名方案、证书解析与文件哈希元数据。"""

    def setUp(self):
        self.samples = glob.glob(os.path.join(ROOT_DIR, "testSample", "*.apk"))

    def test_malformed_signing_block(self):
        """pair_len 为 0/超大时不得把文件尾部整块读进内存，结果为未签名。

        旧实现 pair_len=0 时 read(-4) 会"读到 EOF"把剩余文件全部载入，
        超大 pair_len 则按给定长度整块预分配内存。
        """
        for pair_len in (0, 2 ** 63):
            fd, path = tempfile.mkstemp(prefix="winapkinfo-badsig-", suffix=".apk")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(_signing_block_apk_bytes(pair_len))
                sig = sig_mod.extract_apk_signatures(path)
            finally:
                os.remove(path)
            self.assertEqual(sig, {"schemes": [], "certificates": []})

    def test_file_metadata_and_hashes(self):
        if not self.samples:
            self.skipTest("testSample 目录无 APK 样本")
        apk = self.samples[0]
        meta = sig_mod.get_file_meta_and_hashes(apk)
        self.assertIn("size_bytes", meta)
        self.assertGreater(meta["size_bytes"], 0)
        self.assertEqual(len(meta["md5"]), 32)
        self.assertEqual(len(meta["sha1"]), 40)
        self.assertEqual(len(meta["sha256"]), 64)

    def test_apk_signatures(self):
        if not self.samples:
            self.skipTest("testSample 目录无 APK 样本")
        for apk in self.samples:
            sig = sig_mod.extract_apk_signatures(apk)
            self.assertIsInstance(sig["schemes"], list)
            self.assertGreater(len(sig["schemes"]), 0, f"{apk} 应至少包含一种签名方案")
            self.assertIsInstance(sig["certificates"], list)
            if sig["certificates"]:
                cert = sig["certificates"][0]
                self.assertIn("subject", cert)
                self.assertIn("issuer", cert)
                self.assertIn("sha256", cert)

    def test_signature_report_text(self):
        if not self.samples:
            self.skipTest("testSample 目录无 APK 样本")
        report = sig_mod.get_apk_full_signature_report(self.samples[0])
        self.assertIn("[文件基本属性]", report)
        self.assertIn("[APK 签名方案]", report)
        self.assertIn("SHA-256:", report)


class TestCacheManagement(unittest.TestCase):
    """测试缓存容量、缓存键与磁盘缓存统计逻辑。"""

    def test_memory_byte_cap(self):
        cache = aapt_mod._Aapt2OutputCache(capacity=10, disk_dir=None, mem_max_bytes=100)
        cache.put(("m1",), "x" * 60)
        cache.put(("m2",), "x" * 60)
        self.assertEqual(len(cache._cache), 1)
        self.assertIsNone(cache.get(("m1",)))
        self.assertEqual(cache.get(("m2",)), "x" * 60)

    def test_cache_key_is_versioned(self):
        key = aapt_mod._aapt2_cache_key(__file__, "badging")
        self.assertEqual(len(key), 7)
        self.assertGreaterEqual(key[5], 1)
        self.assertIsInstance(key[6], tuple)

    def test_disk_cache_info_and_clear(self):
        # 必须用临时目录：clear_disk_cache 会删除真实用户缓存
        tmp = tempfile.mkdtemp(prefix="winapkinfo-test-cache-")
        cache = aapt_mod._Aapt2OutputCache(disk_dir=tmp)
        try:
            with mock.patch.object(aapt_mod, "_aapt2_cache", cache), \
                    mock.patch.object(aapt_mod, "_default_disk_cache_dir", return_value=tmp):
                cache.put(("unit-test",), "cached-text")
                info = aapt_mod.get_disk_cache_info()
                self.assertIn("dir", info)
                self.assertIn("count", info)
                self.assertIn("total_bytes", info)
                self.assertEqual(info["count"], 1)
                self.assertIsInstance(info["total_mb"], (int, float))

                freed = aapt_mod.clear_disk_cache()
                self.assertGreater(freed, 0)
                self.assertIsNone(cache.get(("unit-test",)))
                self.assertEqual(aapt_mod.get_disk_cache_info()["count"], 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestResourceIndex(unittest.TestCase):
    """测试基于 _LazyEntryMap 的资源索引惰性切片。"""

    def test_lazy_entry_map(self):
        text = "line1\nresource 0x7f010001\nvalue1\nresource 0x7f010002\nvalue2\n"
        m = res_mod._LazyEntryMap(text)
        dict.__setitem__(m, "0x7f010001", (6, 33))
        self.assertIn("0x7f010001", m)
        self.assertEqual(m["0x7f010001"], "resource 0x7f010001\nvalue1\n")
        self.assertEqual(m.get("0x7f010001"), "resource 0x7f010001\nvalue1\n")
        self.assertIsNone(m.get("0x99999999"))


_NAMED_ALIAS_FULL_RES = (
    "resource 0x7f080162 drawable/fg\n"
    "    () (file) res/Tx.xml type=XML\n"
    "resource 0x7f0600f1 color/adaptive_bg\n"
    "    () @color/brand\n"
    "resource 0x7f0600ee color/brand\n"
    "    () #ff0096fa\n"
)


class TestNamedResourceAlias(unittest.TestCase):
    """aapt2 2.20+ 对表内引用输出 `() @type/name` 命名别名（pixiv 6.201 的
    adaptive 背景即此形态），旧实现只认 `() @0x...` 数字别名，导致背景层
    被判为 unknown、图标提取失败。

    完整的失败链路见该样本的 e2e 用例与资源条目：
        color/adaptive_bg -> @color/brand -> #ff0096fa（pixiv 蓝）
    """

    def test_named_alias_parsed_as_ref(self):
        info = res_mod.get_resource_info(
            "resource 0x7f0600f1 color/bg\n"
            "    () @color/feature_component_charcoal_brand\n"
        )
        self.assertEqual(info, {"type": "ref", "value": "color/feature_component_charcoal_brand"})

    def test_numeric_alias_still_parsed(self):
        info = res_mod.get_resource_info(
            "resource 0x7f0600f1 color/bg\n"
            "    () @0x0106003b\n"
        )
        self.assertEqual(info, {"type": "ref", "value": "0x0106003b"})

    def test_extract_entry_by_name_with_index(self):
        index = res_mod.ResourceIndex(_NAMED_ALIAS_FULL_RES)
        self.assertIn("#ff0096fa", res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "color/brand", index))
        # @ 前缀可带可不带；数字地址不受影响
        self.assertIn("res/Tx.xml", res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "@drawable/fg", index))
        self.assertIn("res/Tx.xml", res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "0x7f080162", index))
        # 框架包前缀的命名引用不在应用表内，查不到返回空串
        self.assertEqual(res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "android:color/white", index), "")

    def test_extract_entry_by_name_without_index(self):
        self.assertIn("#ff0096fa", res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "@color/brand"))
        self.assertIn("res/Tx.xml", res_mod.extract_resource_entry(_NAMED_ALIAS_FULL_RES, "drawable/fg"))

    def test_named_alias_case_preserved(self):
        text = ("resource 0x7f060001 color/Bg\n"
                "    () @color/Brand\n"
                "resource 0x7f060002 color/Brand\n"
                "    () #ff112233\n")
        index = res_mod.ResourceIndex(text)
        kind, value, scale = apk_parser_mod.resolve_icon_layer("f.apk", text, "0x7f060001", index=index)
        self.assertEqual((kind, value, scale), ("color", "#ff112233", None))

    def test_resolve_icon_layer_follows_named_alias(self):
        index = res_mod.ResourceIndex(_NAMED_ALIAS_FULL_RES)
        kind, value, scale = apk_parser_mod.resolve_icon_layer(
            "f.apk", _NAMED_ALIAS_FULL_RES, "0x7f0600f1", index=index)
        self.assertEqual((kind, value, scale), ("color", "#ff0096fa", None))

    def test_resolve_vector_fill_follows_named_alias(self):
        self.assertEqual(
            vec_mod._resolve_vector_fill("f.apk", _NAMED_ALIAS_FULL_RES, "@color/brand"),
            ("color", (0x00, 0x96, 0xfa, 0xff)))
        # 数字引用行为不变
        self.assertEqual(
            vec_mod._resolve_vector_fill("f.apk", _NAMED_ALIAS_FULL_RES, "@0x7f0600ee"),
            ("color", (0x00, 0x96, 0xfa, 0xff)))


class TestVectorRasterization(unittest.TestCase):
    """测试 Qt 原生矢量路径构造与光栅化。"""

    def test_cmds_to_qpainterpath(self):
        # 简单矩形与贝塞尔曲线命令
        cmds = [
            ("M", [0.0, 0.0]),
            ("L", [10.0, 0.0]),
            ("C", [15.0, 5.0, 15.0, 15.0, 10.0, 20.0]),
            ("Z", []),
        ]
        m = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
        qpath = vec_mod._cmds_to_qpainterpath(cmds, m, "nonzero")
        self.assertFalse(qpath.isEmpty())

    def test_vector_clip_path(self):
        """测试 <clip-path> 矢量裁剪路径支持（Qt 与 Pillow 后端）。"""
        xml_clip = (
            "E: vector (line=1)\n"
            "  A: android:viewportWidth(0x01010402)=100.0\n"
            "  A: android:viewportHeight(0x01010403)=100.0\n"
            "  E: group (line=4)\n"
            "    E: clip-path (line=5)\n"
            "      A: android:pathData(0x010100d0)=\"M 0,0 L 50,0 L 50,50 L 0,50 Z\"\n"
            "    E: path (line=7)\n"
            "      A: android:pathData(0x010100d0)=\"M 0,0 L 100,0 L 100,100 L 0,100 Z\"\n"
            "      A: android:fillColor(0x010100d1)=\"#ffff0000\"\n"
        )
        with mock.patch("core.vector.run_aapt2_dump_xmltree", return_value=xml_clip):
            # 1. Qt 光栅化后端
            img_qt = vec_mod._rasterize_vector_layer_qt("x.apk", "res/icon.xml", 100)
            self.assertIsNotNone(img_qt)
            p_in_qt = img_qt.getpixel((25, 25))
            self.assertEqual(p_in_qt[0], 255)
            self.assertGreaterEqual(p_in_qt[3], 240)
            p_out_qt = img_qt.getpixel((75, 75))
            self.assertEqual(p_out_qt[3], 0)

            # 2. Pillow 光栅化回退后端
            img_pil = vec_mod._rasterize_vector_layer_pil("x.apk", "res/icon.xml", 100)
            self.assertIsNotNone(img_pil)
            p_in_pil = img_pil.getpixel((25, 25))
            self.assertEqual(p_in_pil[0], 255)
            self.assertGreaterEqual(p_in_pil[3], 240)
            p_out_pil = img_pil.getpixel((75, 75))
            self.assertEqual(p_out_pil[3], 0)


class TestVectorElementParsing(unittest.TestCase):
    """aapt2 dump xmltree 属性值解析的格式兼容。"""

    def test_old_type_prefix_reference(self):
        """旧版 aapt2 的资源引用带 (type 0x1) 前缀：不剥掉的话取值截断成
        空串，fill/stroke 颜色整层丢失（渲染成透明）。"""
        xml = (
            "E: vector (line=1)\n"
            "  A: http://schemas.android.com/apk/res/android:viewportWidth(0x01010402)=108\n"
            "  E: path (line=2)\n"
            "    A: http://schemas.android.com/apk/res/android:fillColor(0x01010404)=(type 0x1)0x7f060000\n"
            "    A: http://schemas.android.com/apk/res/android:pathData(0x01010405)=\"M0,0h108v108H0z\"\n"
        )
        elems = vec_mod._parse_vector_elements(xml)
        path = next(el for el in elems if el["tag"] == "path")
        self.assertEqual(path["attrs"]["fillColor"], "0x7f060000")
        self.assertEqual(path["attrs"]["pathData"], "M0,0h108v108H0z")

    def test_old_format_reference_resolves_to_color(self):
        """剥掉 (type 0x1) 前缀后，旧格式引用要能走通 _resolve_vector_fill 取色。"""
        full_res = "resource 0x7f060000 color/brand\n    () #ff0096fa\n"
        xml = (
            "E: path (line=1)\n"
            "    A: http://schemas.android.com/apk/res/android:fillColor(0x01010404)=(type 0x1)0x7f060000\n"
        )
        fill_color = vec_mod._parse_vector_elements(xml)[0]["attrs"]["fillColor"]
        self.assertEqual(
            vec_mod._resolve_vector_fill("f.apk", full_res, fill_color),
            ("color", (0x00, 0x96, 0xfa, 0xff)))

    def test_new_reference_and_inline_values_unchanged(self):
        """新版 aapt2（@0x... 引用、内联色、维度值）的解析行为不变。"""
        xml = (
            "E: vector (line=1)\n"
            "  E: path (line=2)\n"
            "    A: http://schemas.android.com/apk/res/android:fillColor(0x01010404)=#ff6750a4\n"
            "  E: path (line=3)\n"
            "    A: http://schemas.android.com/apk/res/android:fillColor(0x01010404)=@0x7f060000\n"
            "  E: path (line=4)\n"
            "    A: http://schemas.android.com/apk/res/android:strokeWidth(0x01010424)=2.500000dp\n"
        )
        paths = [el for el in vec_mod._parse_vector_elements(xml) if el["tag"] == "path"]
        self.assertEqual(paths[0]["attrs"]["fillColor"], "#ff6750a4")
        self.assertEqual(paths[1]["attrs"]["fillColor"], "@0x7f060000")
        self.assertEqual(paths[2]["attrs"]["strokeWidth"], "2.500000dp")


class TestIconTypeSniffing(unittest.TestCase):
    """混淆 APK 的资源路径可能没有扩展名，提取链必须按魔数兜底。"""

    def test_extensionless_png_is_extracted(self):
        buf = io.BytesIO()
        Image.new("RGBA", (16, 16), (255, 0, 0, 255)).save(buf, format="PNG")

        fd, apk_path = tempfile.mkstemp(suffix=".apk", prefix="winapkinfo-test-")
        os.close(fd)
        try:
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("res/Ab", buf.getvalue())
            image, data = IconWorker()._extract(apk_path, "res/Ab")
            self.assertFalse(image.isNull())
            self.assertTrue(data.startswith(b"\x89PNG"))
        finally:
            os.remove(apk_path)


class TestSmartIconExportNaming(unittest.TestCase):
    """测试导出图标智能命名与路径定位逻辑。"""

    def test_sanitize_filename(self):
        self.assertEqual(apk_parser_mod.sanitize_filename("app_icon", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod.sanitize_filename("app_icon.png", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod.sanitize_filename("app_icon.PNG", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod.sanitize_filename("微信_8.0.1", ext=".png"), "微信_8.0.1.png")
        self.assertEqual(apk_parser_mod.sanitize_filename("CON", ext=".png"), "_CON.png")
        self.assertEqual(apk_parser_mod.sanitize_filename('a/b:c*?"<>|', ext=".png"), "a_b_c______.png")
        self.assertEqual(apk_parser_mod.sanitize_filename("   ", ext=".png"), "")
        self.assertEqual(apk_parser_mod.sanitize_filename("test... ", ext=".png"), "test.png")

    def test_default_export_icon_path(self):
        _ = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
        win = MainWindow()
        try:
            # 1. 默认兜底
            self.assertEqual(win._default_export_icon_path(), "app_icon.png")

            # 2. 只有包名
            win.le_pkg.setText("com.example.demo")
            self.assertEqual(win._default_export_icon_path(), "com.example.demo_icon.png")

            # 3. 只有应用名
            win.le_app_name.setText("示例应用")
            self.assertEqual(win._default_export_icon_path(), "示例应用_icon.png")

            # 4. 应用名 + 版本
            win.le_ver.setText("1.2.3 / 102")
            self.assertEqual(win._default_export_icon_path(), "示例应用_1.2.3_icon.png")

            # 5. 重命名预览微调优先
            win.rename_preview.setText("MyCustomApp_v2.0.apk")
            self.assertEqual(win._default_export_icon_path(), "MyCustomApp_v2.0_icon.png")

            # 6. 带真实 APK 路径时，输出应位于 APK 所在目录
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp_apk = tmp.name
            try:
                win._apk_path = tmp_apk
                export_path = win._default_export_icon_path()
                expected_dir = os.path.dirname(os.path.abspath(tmp_apk))
                self.assertEqual(os.path.dirname(export_path), expected_dir)
                self.assertEqual(os.path.basename(export_path), "MyCustomApp_v2.0_icon.png")
            finally:
                if os.path.exists(tmp_apk):
                    os.remove(tmp_apk)
        finally:
            win.close()

    def test_architecture_display(self):
        _ = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
        win = MainWindow()
        try:
            # 纯 Java/Kotlin 应用：无 native 架构
            win.fill_info({"architectures": []}, refresh_icon=False)
            self.assertEqual(win.le_arch.text(), "无 Native 库（纯 Java/Kotlin）")

            # 带架构应用
            win.fill_info({"architectures": ["arm64-v8a", "armeabi-v7a"]}, refresh_icon=False)
            self.assertEqual(win.le_arch.text(), "arm64-v8a, armeabi-v7a")
        finally:
            win.close()


def test_parse_failure_clears_previous_info(app):
    """解析失败后不能把上一个 APK 的名称/包名/权限继续留在界面上。

    旧实现只清空图标与重命名预览，用户会误以为失败文件就是界面上显示的
    APK，复制摘要也会带出旧值。这里直接走 on_apk_info_failed 的真实路径。
    """
    win = MainWindow()
    try:
        win.fill_info({
            "app_name": "Old App",
            "package_name": "com.example.old",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "compile_sdk_version": "33",
            "launchable_activity": "com.example.old.Main",
            "architectures": ["arm64-v8a"],
            "permissions": ["android.permission.INTERNET"],
            "features": ["android.hardware.faketouch"],
            "implied_features": [],
            "locales": ["zh-CN"],
            "supports_screens": ["normal"],
            "densities": ["160"],
            "supports_any_density": "true",
            "app_name_labels": {"zh-CN": "Old App"},
            "icons": {},
        }, refresh_icon=False)
        assert win.le_app_name.text() == "Old App"
        assert win.le_pkg.text() == "com.example.old"

        win._apk_path = "old.apk"
        win.on_apk_info_failed("boom", win._apk_gen)

        for edit in (win.le_app_name, win.le_pkg, win.le_ver,
                     win.le_sdk, win.le_launch, win.le_arch):
            assert edit.text() == "", edit.text()
        for name in ("te_permissions", "te_features", "te_locales", "te_other"):
            assert getattr(win, name)["edit"].toPlainText() == "", name
        assert win.rename_preview.text() == ""
        assert win._raw_output == ""
        assert win._parse_ok_path == ""
        assert win._parsed_info == {}
        assert win._current_icon_bytes is None
        assert win._apk_path == ""
    finally:
        win.close()


class TestBadgingLabelParsing(unittest.TestCase):
    """badging 标签含 aapt2 转义字符（\\'）时的解析回归。

    旧正则 [^']* 在转义引号处提前截断，含撇号的应用名（如
    McDonald's → badging 里写作 McDonald\\'s）会被剪断。
    """

    _BADGING = (
        "package: name='com.example.demo' versionCode='1' versionName='1.0'\n"
        "application-label:'It\\'s OK'\n"
        "application-label-zh-CN:'星\\'际'\n"
        "application: label='McDonald\\'s App' icon='res/ic.png'\n"
        "application-icon-480:'res/ic.png'\n"
    )

    def test_labels_unescaped(self):
        info = apk_parser_mod.parse_aapt2_output(self._BADGING)
        self.assertEqual(info["app_name_labels"]["zh-CN"], "星'际")
        # 中文 locale 存在时优先
        self.assertEqual(info["app_name"], "星'际")

    def test_generic_label_unescaped(self):
        text = self._BADGING.replace("application-label-zh-CN:'星\\'际'\n", "")
        info = apk_parser_mod.parse_aapt2_output(text)
        self.assertEqual(info["app_name"], "It's OK")

    def test_app_node_label_fallback_unescaped(self):
        text = self._BADGING.replace("application-label:'It\\'s OK'\n", "")
        text = text.replace("application-label-zh-CN:'星\\'际'\n", "")
        info = apk_parser_mod.parse_aapt2_output(text)
        self.assertEqual(info["app_name"], "McDonald's App")

    def test_version_name_and_icon_path_unescaped(self):
        """versionName 与图标路径也是自由字符串，同样必须支持转义引号。"""
        text = (
            "package: name='com.example.demo' versionCode='1' "
            "versionName='8.0 \\'Oreo\\''\n"
            "application-icon-480:'res/ic\\'on.png'\n"
            "launchable-activity: name='com.example.MainActivity'\n"
            "uses-feature: name='android.hardware.faketouch'\n"
        )
        info = apk_parser_mod.parse_aapt2_output(text)
        self.assertEqual(info["version_name"], "8.0 'Oreo'")
        self.assertEqual(info["icons"]["480"], "res/ic'on.png")
        self.assertEqual(info["launchable_activity"], "com.example.MainActivity")
        self.assertEqual(info["features"], ["android.hardware.faketouch"])

    def test_quoted_list_fields(self):
        """supports-screens / densities / locales 一串单引号值的提取。"""
        text = (
            "package: name='a.b' versionCode='1' versionName='1.0'\n"
            "supports-screens: 'small' 'normal' 'xlarge'\n"
            "supports-any-density: 'true'\n"
            "densities: '160' '480'\n"
            "locales: '--_--' 'zh-CN' 'en-US'\n"
        )
        info = apk_parser_mod.parse_aapt2_output(text)
        self.assertEqual(info["supports_screens"], ["small", "normal", "xlarge"])
        self.assertEqual(info["supports_any_density"], "true")
        self.assertEqual(info["densities"], ["160", "480"])
        self.assertEqual(info["locales"], ["--_--", "zh-CN", "en-US"])

    def test_permissions_extraction_and_sdk23(self):
        text = (
            "package: name='com.example.demo' versionCode='1' versionName='1.0'\n"
            "uses-permission: name='android.permission.INTERNET'\n"
            "uses-permission-sdk-23: name='android.permission.REQUEST_INSTALL_PACKAGES'\n"
            "uses-permission-sdk-23: name='android.permission.WRITE_EXTERNAL_STORAGE' maxSdkVersion='28'\n"
            "uses-permission: name='android.permission.INTERNET'\n"
            "uses-permission: name='com.example.CUSTOM\\'PERMISSION'\n"
        )
        info = apk_parser_mod.parse_aapt2_output(text)
        self.assertEqual(
            info["permissions"],
            [
                "android.permission.INTERNET",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "com.example.CUSTOM'PERMISSION",
            ],
        )


_VECTOR_ICON_XML = (
    "E: vector (line=1)\n"
    "  A: http://schemas.android.com/apk/res/android:viewportWidth(0x01010402)=108.0\n"
)
_VECTOR_FULL_RES = (
    "resource 0x7f010001 res/color/c0\n"
    "    () #ff0000\n"
)


def test_vector_icon_reuses_resource_index(monkeypatch):
    """普通 VectorDrawable 图标必须复用一次性资源索引。

    回归 1.1：root==vector 分支此前不传 full_res/index，每个
    fillColor/strokeColor 引用都会走无索引路径，对整个 dump 重复
    splitlines + 线性扫描（36MB dump 单次约 0.17s）。
    """
    captured = {}

    def fake_rasterize(apk_path, xml_path, size, full_res=None, index=None):
        captured["full_res"] = full_res
        captured["index"] = index
        return Image.new("RGBA", (size, size), (255, 0, 0, 255))

    monkeypatch.setattr(workers_mod, "rasterize_vector_layer", fake_rasterize)
    monkeypatch.setattr(workers_mod, "run_aapt2_dump_xmltree", lambda apk, path: _VECTOR_ICON_XML)
    monkeypatch.setattr(workers_mod, "run_aapt2_dump_resource", lambda apk: _VECTOR_FULL_RES)

    data = IconWorker()._extract_adaptive_icon("x.apk", "res/icon.xml")
    assert captured.get("index") is not None, "vector 图标分支必须透传资源索引"
    assert captured.get("full_res") == _VECTOR_FULL_RES
    assert data.startswith(b"\x89PNG")


class TestMiniFixtureAPK(unittest.TestCase):
    """迷你 APK 固件：CI 上也能跑的端到端链路（badging → 图标提取）。

    testSample/ 不入库，CI 此前只验证 aapt2 可运行；固件由
    scripts/make_mini_apk.py 生成并入库，覆盖自适应图标 + 矢量栅格化
    与位图归一化两条路径。
    """

    FIXTURE = os.path.join(ROOT_DIR, "tests", "fixtures", "mini.apk")

    def setUp(self):
        if not os.path.isfile(self.FIXTURE):
            self.skipTest("缺少 tests/fixtures/mini.apk（运行 scripts/make_mini_apk.py 生成）")
        try:
            aapt_mod.find_aapt2()
        except Exception as e:
            self.skipTest("aapt2 不可用：%s" % e)

    def test_badging(self):
        info = apk_parser_mod.parse_aapt2_output(
            aapt_mod.run_aapt2_dump_badging(self.FIXTURE))
        self.assertEqual(info["package_name"], "com.example.miniapk")
        self.assertEqual(info["version_name"], "1.0")
        self.assertTrue(info["icons"], "固件应包含 application-icon 条目")
        self.assertTrue(any(p.lower().endswith(".xml") for p in info["icons"].values()))

    def test_adaptive_and_bitmap_icon(self):
        info = apk_parser_mod.parse_aapt2_output(
            aapt_mod.run_aapt2_dump_badging(self.FIXTURE))
        xml_icon = max(info["icons"].items(), key=lambda kv: int(kv[0]))[1]
        image, data = IconWorker()._extract(self.FIXTURE, xml_icon)
        self.assertFalse(image.isNull())
        self.assertEqual((image.width(), image.height()), (512, 512))
        self.assertTrue(data.startswith(b"\x89PNG"))

        full_res = aapt_mod.run_aapt2_dump_resource(self.FIXTURE) or ""
        pngs = re.findall(r"\(file\)\s*(res/\S+\.png)", full_res)
        self.assertTrue(pngs, "固件应包含位图图标")
        image2, data2 = IconWorker()._extract(self.FIXTURE, pngs[-1])
        self.assertEqual((image2.width(), image2.height()), (512, 512))
        self.assertTrue(data2.startswith(b"\x89PNG"))


class TestGradientRendering(unittest.TestCase):
    """渐变解析与渲染的回归守护。"""

    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])

    _XML = """E: gradient (line=1)
  A: http://schemas.android.com/apk/res/android:startColor(0x0101)=#ff0000ff
  A: http://schemas.android.com/apk/res/android:centerColor(0x0101)=#ff00ff00
  A: http://schemas.android.com/apk/res/android:endColor(0x0101)=#ffff0000
  A: http://schemas.android.com/apk/res/android:angle(0x0101)=90.0
"""

    _VECTOR = """E: vector (line=1)
  A: http://schemas.android.com/apk/res/android:viewportWidth(0x0101)=100.0
  A: http://schemas.android.com/apk/res/android:viewportHeight(0x0101)=100.0
  E: path (line=2)
    A: http://schemas.android.com/apk/res/android:pathData(0x0101)="M0,0 L100,0 L100,100 L0,100 Z"
    A: http://schemas.android.com/apk/res/android:fillColor(0x0101)=@0x7f010001
"""

    _FULL_RES = """resource 0x7f010001 res/grad
    () (file) res/grad.xml type=XML
"""

    def test_start_center_end_colors(self):
        grad = vec_mod._parse_gradient(self._XML)
        self.assertIsNotNone(grad)
        self.assertEqual([round(stop[0], 2) for stop in grad["stops"]], [0.0, 0.5, 1.0])
        self.assertEqual(grad["stops"][0][1], (0, 0, 255, 255))
        self.assertEqual(grad["stops"][-1][1], (255, 0, 0, 255))

    def test_angle_only_linear_gradient_spans_canvas(self):
        grad = {
            "type": 0, "startX": 0.0, "startY": 0.0, "endX": 0.0, "endY": 0.0,
            "centerX": 0.0, "centerY": 0.0, "radius": 0.0, "angle": 90.0,
            "stops": [(0.0, (0, 0, 255, 255)), (1.0, (255, 0, 0, 255))],
        }
        img = vec_mod._render_gradient(8, 8, grad, (1.0, 0.0, 0.0, 1.0, 0.0, 0.0))
        # angle=90 表示下→上：底部应接近 startColor，顶部应接近 endColor
        self.assertNotEqual(img.getpixel((0, 0)), img.getpixel((0, 7)))

    def test_scale_alpha_keeps_rgb(self):
        src = Image.new("RGBA", (1, 1), (255, 0, 0, 255))
        out = vec_mod._scale_alpha(src, 0.5)
        self.assertEqual(out.getpixel((0, 0))[:3], (255, 0, 0))
        self.assertEqual(out.getpixel((0, 0))[3], 128)

    def test_stroke_mask_and_color_stroke(self):
        subpaths = [[(2, 8), (14, 8)]]
        mask = vec_mod._stroke_mask((16, 16), subpaths, 4, 0)
        self.assertIsNotNone(mask.getbbox())

        layer = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
        vec_mod._draw_stroke(layer, subpaths, (255, 0, 0, 255), 0.5, 4, 0)
        pixel = layer.getpixel((8, 8))
        self.assertEqual(pixel[:3], (255, 0, 0))
        self.assertEqual(pixel[3], 128)

    def test_start_end_gradient_renders_in_both_backends(self):
        """startColor/endColor + angle 必须同时被 Qt 与 Pillow 渲染链路识别。"""

        def dump_xml(_apk, path):
            return self._XML if path == "res/grad.xml" else self._VECTOR

        for renderer in (vec_mod._rasterize_vector_layer_pil, vec_mod._rasterize_vector_layer_qt):
            with mock.patch.object(vec_mod, "run_aapt2_dump_xmltree", side_effect=dump_xml):
                img = renderer("fake.apk", "res/icon.xml", 64, full_res=self._FULL_RES)
            self.assertIsNotNone(img)
            # angle=90 表示下→上：顶部偏 endColor 红，底部偏 startColor 蓝
            top = img.getpixel((32, 2))
            bottom = img.getpixel((32, 61))
            self.assertGreater(top[0], top[2], f"{renderer.__name__} top={top}")
            self.assertGreater(bottom[2], bottom[0], f"{renderer.__name__} bottom={bottom}")


# ---------------------------------------------------------------------------
# 回归检查（tests/regression_checks.py）：历史修复的行为守护
# ---------------------------------------------------------------------------
def test_env():
    regression_checks.check_env()


def test_p0_1_fill_type():
    regression_checks.check_p0_1()


def test_p0_2_smooth_control_points():
    regression_checks.check_p0_2()


def test_p0_3_stroke_line_cap():
    regression_checks.check_p0_3()


def test_p1_4_slot_exception(app):
    regression_checks.check_p1_4(app)


def test_p1_5_aapt2_timeout_and_abort(app):
    regression_checks.check_p1_5(app)


def test_p1_6_icon_worker_channel(app):
    regression_checks.check_p1_6(app)


def test_p1_7_process_apk_path(app):
    regression_checks.check_p1_7(app)


def test_p1_8_icon_failed_hint(app):
    regression_checks.check_p1_8(app)


def test_d3_supersede(app):
    regression_checks.check_d3_supersede(app)


def test_p2_9_fill_mask_chunking():
    regression_checks.check_p2_9()


def test_p2_10_find_aapt2_cache():
    regression_checks.check_p2_10()


def test_p2_11_disk_cache():
    regression_checks.check_p2_11()


def test_p2_12_rgba_resize_premultiplication():
    regression_checks.check_p2_12()


def test_a1_excepthook_thread_safety(app):
    regression_checks.check_a1(app)


def test_b1_non_vector_fallback(app):
    regression_checks.check_b1(app)


def test_b2_cache_byte_cap():
    regression_checks.check_b2(False)


def test_b3_sdk_versions_reload():
    regression_checks.check_b3()


def test_new_fixes_regression():
    regression_checks.check_new_fixes()


@pytest.mark.e2e
def test_end_to_end(app):
    """真实样本端到端（默认构建不跑；`-m e2e` 或完整运行才包含）。"""
    if not regression_checks.sample_apks():
        pytest.skip("testSample 目录无 APK 样本")
    regression_checks.check_end_to_end(app, None)
