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


class TestSignatureAndMeta(unittest.TestCase):
    """测试 APK 签名方案、证书解析与文件哈希元数据。"""

    def setUp(self):
        self.samples = glob.glob(os.path.join(ROOT_DIR, "testSample", "*.apk"))

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
        self.assertEqual(apk_parser_mod._sanitize_filename("app_icon", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod._sanitize_filename("app_icon.png", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod._sanitize_filename("app_icon.PNG", ext=".png"), "app_icon.png")
        self.assertEqual(apk_parser_mod._sanitize_filename("微信_8.0.1", ext=".png"), "微信_8.0.1.png")
        self.assertEqual(apk_parser_mod._sanitize_filename("CON", ext=".png"), "_CON.png")
        self.assertEqual(apk_parser_mod._sanitize_filename('a/b:c*?"<>|', ext=".png"), "a_b_c______.png")
        self.assertEqual(apk_parser_mod._sanitize_filename("   ", ext=".png"), "")
        self.assertEqual(apk_parser_mod._sanitize_filename("test... ", ext=".png"), "test.png")

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
