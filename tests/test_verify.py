# -*- coding: utf-8 -*-
"""标准测试适配入口，支持 pytest 与 python -m unittest 自动发现执行。"""
import os
import sys
import glob
import unittest

# 确保项目根目录在 sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from PyQt6 import QtWidgets
import core.aapt as aapt_mod
import core.signature as sig_mod
import core.resources as res_mod
import core.vector as vec_mod
import ui.main_window as mw_mod
import verify_fixes


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
    """测试磁盘缓存统计与清空逻辑。"""

    def test_disk_cache_info_and_clear(self):
        info = aapt_mod.get_disk_cache_info()
        self.assertIn("dir", info)
        self.assertIn("count", info)
        self.assertIn("total_bytes", info)
        self.assertIsInstance(info["total_mb"], (int, float))

        # 测试清空逻辑能安全调用不崩溃
        freed = aapt_mod.clear_disk_cache()
        self.assertGreaterEqual(freed, 0)


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
