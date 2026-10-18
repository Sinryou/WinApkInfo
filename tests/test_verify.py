# -*- coding: utf-8 -*-
"""标准测试适配入口，支持 pytest 与 python -m unittest 自动发现执行。"""
import io
import os
import sys
import glob
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

# 确保项目根目录在 sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from PyQt6 import QtWidgets
import core.aapt as aapt_mod
import core.signature as sig_mod
import core.resources as res_mod
import core.vector as vec_mod
import verify_fixes
from PIL import Image
from ui.workers import IconWorker


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


class TestRegressionSuite(unittest.TestCase):
    """执行全部合成用例回归检查（验证通过率）。"""

    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
        verify_fixes.silence_dialogs()

    def test_quick_regressions(self):
        verify_fixes.C.results = []
        verify_fixes.C.skipped = []
        verify_fixes.check_env()
        verify_fixes.check_p0_1()
        verify_fixes.check_p0_2()
        verify_fixes.check_p0_3()
        verify_fixes.check_p1_4(self.app)
        verify_fixes.check_p1_5(self.app)
        verify_fixes.check_p1_6(self.app)
        verify_fixes.check_p1_7(self.app)
        verify_fixes.check_p1_8(self.app)
        verify_fixes.check_p2_9()
        verify_fixes.check_p2_10()
        verify_fixes.check_p2_12()
        verify_fixes.check_a1(self.app)
        verify_fixes.check_b1(self.app)
        verify_fixes.check_b2(False)
        verify_fixes.check_b3()
        verify_fixes.check_new_fixes()
        failed = [r for r in verify_fixes.C.results if not r[2]]
        self.assertEqual(len(failed), 0, f"存在回归失败项: {failed}")


if __name__ == "__main__":
    unittest.main()
