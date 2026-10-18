# -*- coding: utf-8 -*-
"""APK 文件属性、哈希校验与签名证书解析（v1/v2/v3/v3.1）。"""
import os
import ssl
import struct
import hashlib
import zipfile
import datetime
import tempfile
import logging

try:
    import _ssl
except ImportError:
    _ssl = None


def get_file_meta_and_hashes(apk_path: str) -> dict:
    """计算 APK 文件大小、修改时间与 MD5 / SHA1 / SHA256 哈希。"""
    if not apk_path or not os.path.isfile(apk_path):
        return {}
    try:
        st = os.stat(apk_path)
    except OSError:
        return {}

    size_bytes = st.st_size
    if size_bytes < 1024:
        size_str = f"{size_bytes} 字节"
    elif size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.2f} KB ({size_bytes:,} 字节)"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB ({size_bytes:,} 字节)"

    mtime_str = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    md5_h = hashlib.md5()
    sha1_h = hashlib.sha1()
    sha256_h = hashlib.sha256()

    try:
        with open(apk_path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                md5_h.update(chunk)
                sha1_h.update(chunk)
                sha256_h.update(chunk)
    except Exception as e:
        logging.warning("计算文件哈希失败 (%s): %s", apk_path, e)
        return {
            "size_bytes": size_bytes,
            "size_str": size_str,
            "mtime": mtime_str,
            "md5": "(计算失败)",
            "sha1": "(计算失败)",
            "sha256": "(计算失败)",
        }

    return {
        "size_bytes": size_bytes,
        "size_str": size_str,
        "mtime": mtime_str,
        "md5": md5_h.hexdigest().upper(),
        "sha1": sha1_h.hexdigest().upper(),
        "sha256": sha256_h.hexdigest().upper(),
    }


def _format_fingerprint(data: bytes, algo: str) -> str:
    """计算并格式化十六进制冒号分隔的证书指纹。"""
    try:
        h = getattr(hashlib, algo)(data).hexdigest().upper()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    except Exception:
        return ""


def _parse_x509_der(cert_der: bytes) -> dict:
    """解析单个 DER 编码的 X.509 证书。"""
    info = {
        "subject": "(未知)",
        "issuer": "(未知)",
        "serial_number": "",
        "not_before": "",
        "not_after": "",
        "md5": _format_fingerprint(cert_der, "md5"),
        "sha1": _format_fingerprint(cert_der, "sha1"),
        "sha256": _format_fingerprint(cert_der, "sha256"),
    }
    if not cert_der:
        return info

    try:
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
    except Exception:
        return info

    if _ssl and hasattr(_ssl, "_test_decode_cert"):
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w", encoding="ascii") as tmp:
                tmp.write(pem)
                tmp_path = tmp.name
            try:
                decoded = _ssl._test_decode_cert(tmp_path)
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            def _fmt_dn(dn_tuple):
                if not dn_tuple:
                    return ""
                parts = []
                for rdn in dn_tuple:
                    for k, v in rdn:
                        parts.append(f"{k}={v}")
                return ", ".join(parts)

            info["subject"] = _fmt_dn(decoded.get("subject", ())) or "(未指定)"
            info["issuer"] = _fmt_dn(decoded.get("issuer", ())) or "(未指定)"
            info["serial_number"] = str(decoded.get("serialNumber", ""))
            info["not_before"] = str(decoded.get("notBefore", ""))
            info["not_after"] = str(decoded.get("notAfter", ""))
        except Exception as e:
            logging.debug("解码 X.509 证书失败: %s", e)

    return info


def extract_apk_signatures(apk_path: str) -> dict:
    """解析 APK 的签名方案（v1/v2/v3/v3.1）并提取证书详细属性。"""
    if not apk_path or not os.path.isfile(apk_path):
        return {"schemes": [], "certificates": []}

    schemes = []
    certs_raw = []  # [(scheme, der_bytes)]
    seen_fingerprints = set()

    # 1. 探测 v1 (JAR 签名)
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            v1_files = [
                n for n in zf.namelist()
                if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
            ]
            if v1_files:
                schemes.append("v1 (JAR Signature)")
                for vf in v1_files:
                    try:
                        data = zf.read(vf)
                        idx = 0
                        while True:
                            pos = data.find(b"\x30\x82", idx)
                            if pos == -1 or pos + 4 > len(data):
                                break
                            c_len = struct.unpack(">H", data[pos + 2:pos + 4])[0] + 4
                            if pos + c_len <= len(data):
                                candidate = data[pos:pos + c_len]
                                try:
                                    ssl.DER_cert_to_PEM_cert(candidate)
                                    certs_raw.append(("v1", candidate))
                                    break
                                except Exception:
                                    pass
                            idx = pos + 2
                    except Exception:
                        pass
    except Exception as e:
        logging.debug("检查 v1 签名异常: %s", e)

    # 2. 探测 APK Signing Block (v2, v3, v3.1)
    try:
        with open(apk_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            scan_len = min(size, 65536)
            f.seek(size - scan_len)
            data = f.read(scan_len)
            eocd_pos = data.rfind(b"\x50\x4b\x05\x06")
            if eocd_pos != -1:
                cd_size, cd_offset = struct.unpack("<II", data[eocd_pos + 12:eocd_pos + 20])
                if cd_offset >= 24:
                    f.seek(cd_offset - 24)
                    block_size_end, magic = struct.unpack("<Q16s", f.read(24))
                    if magic == b"APK Sig Block 42":
                        block_start = cd_offset - 8 - block_size_end
                        f.seek(block_start)
                        block_size_start = struct.unpack("<Q", f.read(8))[0]
                        if block_size_start == block_size_end:
                            rem = block_size_end - 24
                            while rem > 8:
                                pair_len, pair_id = struct.unpack("<QI", f.read(12))
                                pair_val = f.read(pair_len - 4)
                                rem -= (8 + pair_len)
                                if pair_id == 0x7109871a:
                                    if "v2 (APK Signature)" not in schemes:
                                        schemes.append("v2 (APK Signature)")
                                elif pair_id == 0xf05368c0:
                                    if "v3 (APK Signature v3)" not in schemes:
                                        schemes.append("v3 (APK Signature v3)")
                                elif pair_id == 0x1b93ad61:
                                    if "v3.1 (APK Signature v3.1)" not in schemes:
                                        schemes.append("v3.1 (APK Signature v3.1)")

                                if pair_id in (0x7109871a, 0xf05368c0):
                                    pos = 0
                                    signers_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]; pos += 4
                                    while pos < 4 + signers_len:
                                        signer_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]; pos += 4
                                        signer_end = pos + signer_len
                                        pos += 4  # signed_data_len
                                        digests_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]; pos += 4 + digests_len
                                        certs_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]; pos += 4
                                        certs_end = pos + certs_len
                                        while pos < certs_end:
                                            cert_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]; pos += 4
                                            cert_der = pair_val[pos:pos + cert_len]; pos += cert_len
                                            scheme_tag = "v2" if pair_id == 0x7109871a else "v3"
                                            certs_raw.append((scheme_tag, cert_der))
                                        pos = signer_end
    except Exception as e:
        logging.debug("检查 APK 签名分块异常: %s", e)

    parsed_certs = []
    for scheme, c_der in certs_raw:
        cert_info = _parse_x509_der(c_der)
        fp_sha256 = cert_info.get("sha256")
        if fp_sha256 and fp_sha256 not in seen_fingerprints:
            seen_fingerprints.add(fp_sha256)
            cert_info["scheme"] = scheme
            parsed_certs.append(cert_info)

    return {
        "schemes": schemes,
        "certificates": parsed_certs,
    }


def get_apk_full_signature_report(apk_path: str) -> str:
    """生成排版整齐的文件属性、哈希与证书签名综合报告文本。"""
    meta = get_file_meta_and_hashes(apk_path)
    sig = extract_apk_signatures(apk_path)

    lines = []
    lines.append("[文件基本属性]")
    if meta:
        lines.append(f"文件大小: {meta.get('size_str', '')}")
        lines.append(f"修改时间: {meta.get('mtime', '')}")
        lines.append(f"MD5:      {meta.get('md5', '')}")
        lines.append(f"SHA-1:    {meta.get('sha1', '')}")
        lines.append(f"SHA-256:  {meta.get('sha256', '')}")
    else:
        lines.append("(无法读取文件属性)")

    lines.append("")
    lines.append("[APK 签名方案]")
    schemes = sig.get("schemes", [])
    if schemes:
        lines.append("支持方案: " + ", ".join(schemes))
    else:
        lines.append("支持方案: (未检测到有效签名，可能为未签名包)")

    certs = sig.get("certificates", [])
    if certs:
        for idx, c in enumerate(certs, 1):
            lines.append("")
            lines.append(f"[签名证书 {idx}]")
            lines.append(f"所有者 (Subject): {c.get('subject', '')}")
            lines.append(f"颁发者 (Issuer):  {c.get('issuer', '')}")
            if c.get("serial_number"):
                lines.append(f"序列号:           {c.get('serial_number')}")
            if c.get("not_before") or c.get("not_after"):
                lines.append(f"有效期:           {c.get('not_before')} 至 {c.get('not_after')}")
            lines.append(f"MD5 指纹:         {c.get('md5', '')}")
            lines.append(f"SHA-1 指纹:       {c.get('sha1', '')}")
            lines.append(f"SHA-256 指纹:     {c.get('sha256', '')}")
    else:
        lines.append("")
        lines.append("[证书信息]")
        lines.append("(无证书数据)")

    return "\n".join(lines)
