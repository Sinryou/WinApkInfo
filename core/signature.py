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
import warnings

try:
    import _ssl
except ImportError:
    _ssl = None

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None
    NameOID = None

# cryptography 的 Name OID → OpenSSL 风格短名，保持与 _ssl 兜底路径
# （_test_decode_cert 即 OpenSSL 的解码）一致的显示格式；未收录的 OID
# 退回点分数字形式。
_DN_ATTR_NAMES = {
    NameOID.COMMON_NAME: "commonName",
    NameOID.COUNTRY_NAME: "countryName",
    NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
    NameOID.LOCALITY_NAME: "localityName",
    NameOID.ORGANIZATION_NAME: "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.DOMAIN_COMPONENT: "domainComponent",
    NameOID.STREET_ADDRESS: "streetAddress",
    NameOID.POSTAL_CODE: "postalCode",
} if NameOID is not None else {}


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


def _der_tlv(data: bytes, pos: int, end: int):
    """读取 pos 处的一个 DER TLV，返回 (tag, content_start, content_end)。

    只需覆盖 PKCS#7 签名块用到的形态：单字节标签、定长长度字段
    （1 字节短格式或 1–4 字节长格式）。越界、畸形或不定长（DER 禁止）
    返回 None。
    """
    if pos + 2 > end:
        return None
    tag = data[pos]
    if tag & 0x1F == 0x1F:  # 多字节标签，PKCS#7 结构里不会出现
        return None
    first = data[pos + 1]
    if first < 0x80:
        hdr, length = 2, first
    elif first == 0x80:
        return None
    else:
        n = first & 0x7F
        if n > 4 or pos + 2 + n > end:
            return None
        length = int.from_bytes(data[pos + 2:pos + 2 + n], "big")
        hdr = 2 + n
    content_start = pos + hdr
    if content_start + length > end:
        return None
    return tag, content_start, content_start + length


def _pkcs7_certificates(data: bytes) -> list:
    """从 PKCS#7/CMS SignedData 签名块（META-INF/*.RSA/.DSA/.EC）提取全部内嵌 X.509 证书 DER。

    结构：ContentInfo{ OID, [0] EXPLICIT SignedData{ version, digestAlgorithms,
    encapContentInfo, [0] IMPLICIT SET OF Certificate, … } }。certificates 是
    IMPLICIT 标签，其内容直接是连排的证书 SEQUENCE。

    旧实现按 \\x30\\x82 字节特征盲扫：首个命中恰是最外层 ContentInfo（覆盖
    整个文件），而"校验"用的 DER_cert_to_PEM_cert 只做 base64 封装、对任何
    字节都不失败，于是整个签名块文件被当成"证书"（指纹是文件的、subject
    恒为未知），真正的证书反而一个都取不到。
    """
    certs = []
    top = _der_tlv(data, 0, len(data))
    if top is None or top[0] != 0x30:  # ContentInfo SEQUENCE
        return certs
    pos = top[1]
    while pos < top[2]:  # ContentInfo 子元素：contentType OID + [0] EXPLICIT content
        child = _der_tlv(data, pos, top[2])
        if child is None:
            break
        pos = child[2]
        if child[0] != 0xA0:
            continue
        signed = _der_tlv(data, child[1], child[2])  # [0] 内的 SignedData SEQUENCE
        if signed is None or signed[0] != 0x30:
            continue
        s_pos = signed[1]
        while s_pos < signed[2]:  # SignedData 子元素，找 [0] IMPLICIT certificates
            field = _der_tlv(data, s_pos, signed[2])
            if field is None:
                break
            s_pos = field[2]
            if field[0] != 0xA0:
                continue
            c_pos = field[1]
            while c_pos < field[2]:  # 连排的证书 SEQUENCE
                cert = _der_tlv(data, c_pos, field[2])
                if cert is None:
                    break
                if cert[0] == 0x30:
                    certs.append(data[c_pos:cert[2]])
                c_pos = cert[2]
    return certs


def _fmt_dn_cryptography(name) -> str:
    """cryptography 的 Name → "key=value, …" 文本（OpenSSL 风格短名）。"""
    parts = []
    for attr in name:
        key = _DN_ATTR_NAMES.get(attr.oid) or attr.oid.dotted_string
        try:
            value = attr.value
        except Exception:
            value = "?"
        parts.append(f"{key}={value}")
    return ", ".join(parts)


def _fill_cert_subject_from_cryptography(info: dict, cert_der: bytes) -> None:
    """用 cryptography 解析证书主体/签发者/序列号/有效期（公开 API 主路径）。"""
    try:
        # 真实证书常见不规范字段值（如 1 字符的 CountryName），cryptography
        # 在 subject/issuer 惰性解析时只发 UserWarning、值仍可用；这类噪音
        # 不必外溢到日志（字段级异常仍由外层 try 兜底）。
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            cert = x509.load_der_x509_certificate(cert_der)
            info["subject"] = _fmt_dn_cryptography(cert.subject) or "(未指定)"
            info["issuer"] = _fmt_dn_cryptography(cert.issuer) or "(未指定)"
            info["serial_number"] = f"{cert.serial_number:X}"
            info["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
            info["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception as e:
        logging.debug("cryptography 解析 X.509 证书失败: %s", e)


def _fill_cert_subject_from_ssl(info: dict, cert_der: bytes) -> None:
    """_ssl._test_decode_cert 兜底路径（cryptography 缺失时才走）。

    该函数是 CPython 的内部测试钩子，无兼容性承诺，且要为每张证书落一个
    临时 PEM 文件；只作为降级路径保留。
    """
    if not (_ssl and hasattr(_ssl, "_test_decode_cert")):
        return
    try:
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
    except Exception:
        return
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


def _parse_x509_der(cert_der: bytes) -> dict:
    """解析单个 DER 编码的 X.509 证书。

    主体/签发者等字段优先用 cryptography（受支持的公开 API）解析；
    缺失时回退 _ssl._test_decode_cert 私有钩子。两种路径都失败时保留
    "(未知)" 默认值，指纹不受影响（直接对 DER 计算）。
    """
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

    if x509 is not None:
        _fill_cert_subject_from_cryptography(info, cert_der)
    else:
        _fill_cert_subject_from_ssl(info, cert_der)
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
                        certs_raw.extend(("v1", c) for c in _pkcs7_certificates(zf.read(vf)))
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
                                header = f.read(12)
                                if len(header) < 12:
                                    break  # 块在 pair 头部处被截断
                                pair_len, pair_id = struct.unpack("<QI", header)
                                # pair_len 是 pair 的总长（4 字节 id + 值），值必须
                                # 留在块内。畸形/伪造的长度会让 read(负数) 变成
                                # "读到 EOF"，或按给定长度整块预分配内存，把大段
                                # 文件读进内存；此时 rem 核算已不可靠，无法定位
                                # 下一对，只能放弃。
                                if pair_len < 4 or pair_len > rem - 8:
                                    break
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
                                    signers_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]
                                    pos += 4
                                    while pos < 4 + signers_len:
                                        signer_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]
                                        pos += 4
                                        signer_end = pos + signer_len
                                        pos += 4  # signed_data_len
                                        digests_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]
                                        pos += 4 + digests_len
                                        certs_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]
                                        pos += 4
                                        certs_end = pos + certs_len
                                        while pos < certs_end:
                                            cert_len = struct.unpack("<I", pair_val[pos:pos + 4])[0]
                                            pos += 4
                                            cert_der = pair_val[pos:pos + cert_len]
                                            pos += cert_len
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
