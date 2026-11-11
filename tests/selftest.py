#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自测脚本：用合成数据验证各解析器不崩、能返回合理结果。

不依赖真实 APK，所以 CI 里也能跑。

    python tests/selftest.py
"""

import base64
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import apk_analyze as A

FAILED = []


def check(name, cond, detail=""):
    if cond:
        print("  ok   %s" % name)
    else:
        print("  FAIL %s   %s" % (name, detail))
        FAILED.append(name)


# --------------------------------------------------------------------------
# 1. 字符串池：UTF-8 分支
# --------------------------------------------------------------------------


def build_string_pool(strings, utf8=True):
    """按 AXML/arsc 的格式造一个字符串池 chunk。"""
    def uleb(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out += bytes([b | 0x80])
            else:
                out += bytes([b])
                return out

    blobs = []
    for s in strings:
        if utf8:
            raw = s.encode("utf-8")
            blobs.append(uleb(len(s)) + uleb(len(raw)) + raw)
        else:
            raw = s.encode("utf-16-le")
            blobs.append(struct.pack("<H", len(s)) + raw)
    data = b""
    offsets = []
    for b in blobs:
        offsets.append(len(data))
        data += b
    while len(data) % 4:
        data += b"\x00"
    count = len(strings)
    header_size = 28
    strings_start = header_size + count * 4
    total = strings_start + len(data)
    chunk = struct.pack("<HHI", 0x0001, header_size, total)
    chunk += struct.pack("<IIIII", count, 0, 0x100 if utf8 else 0, strings_start, 0)
    chunk += b"".join(struct.pack("<I", o) for o in offsets)
    chunk += data
    return chunk


def test_string_pool():
    print("[1] 字符串池")
    ss = ["", "hello", "这是一个中文字符串", "x" * 200]
    for utf8 in (True, False):
        pool = build_string_pool(ss, utf8=utf8)
        got = A.parse_string_pool(pool, 0)
        check("utf8=%s 数量" % utf8, len(got) == len(ss), got)
        check("utf8=%s 内容" % utf8, got == ss, got)

    # 坏偏移不能把程序搞崩，也不能返回几百 MB 的垃圾
    bad = bytearray(build_string_pool(ss))
    struct.pack_into("<I", bad, 28, 0xFFFFFF)      # 第一条偏移改成越界值
    got = A.parse_string_pool(bytes(bad), 0)
    check("坏偏移不崩", len(got) == len(ss), got)
    check("坏偏移返回空串", got[0] == "", got)


# --------------------------------------------------------------------------
# 2. 爱加密解密
# --------------------------------------------------------------------------


def ijiami_encode(plain):
    raw = plain.encode("utf-8")
    mixed = bytes(b ^ A.IJIAMI_KEY[i % len(A.IJIAMI_KEY)]
                  for i, b in enumerate(raw))
    return base64.b64encode(mixed).decode()


def test_ijiami():
    print("[2] 爱加密字符串解密")
    cases = [
        "com.ctZtamt.cym.ilajjtl.MyApplication",
        "com.newskyer.draw",
        "extract_switch_",
        "检测到调试器",
        "当前版本为加固试用版，请勿直接发布上线",
    ]
    for plain in cases:
        enc = ijiami_encode(plain)
        got = A.ijiami_decode(enc)
        check("往返 %s" % plain[:24], got == plain, got)

    # 已知样本（来自真实 APK）
    check("已知样本 wrapper",
          A.ijiami_decode("ORcVFREWFw==") == "wrapper",
          A.ijiami_decode("ORcVFREWFw=="))

    # 噪音过滤
    check("拒绝签名短码", not A.looks_like_real_string("\ufffd\ufffd"))
    check("拒绝纯符号", not A.looks_like_real_string("???"))
    check("接受正常文本", A.looks_like_real_string("hello world"))
    check("接受中文", A.looks_like_real_string("检测到调试器"))


# --------------------------------------------------------------------------
# 3. DEX header
# --------------------------------------------------------------------------


def build_dex(payload_size=1024):
    """造一个"壳 DEX"：合法 header + data 区间 + 一坨填充。"""
    d = bytearray(112 + 4096 + payload_size)
    d[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", d, 0x20, len(d))       # file_size
    struct.pack_into("<I", d, 0x24, 112)          # header_size
    struct.pack_into("<I", d, 0x28, 0x12345678)   # endian_tag
    struct.pack_into("<I", d, 0x34, 112)          # map_off
    struct.pack_into("<I", d, 0x38, 0)            # string_ids_size
    struct.pack_into("<I", d, 0x3C, 112)          # string_ids_off
    struct.pack_into("<I", d, 0x40, 0)            # type_ids_size
    struct.pack_into("<I", d, 0x44, 112)          # type_ids_off
    struct.pack_into("<I", d, 0x60, 0)            # class_defs_size
    struct.pack_into("<I", d, 0x64, 112)          # class_defs_off
    struct.pack_into("<I", d, 0x68, 4096)         # data_size
    struct.pack_into("<I", d, 0x6C, 112)          # data_off
    return bytes(d)


def test_dex():
    print("[3] DEX 加固判定")
    packed = build_dex(payload_size=100 * 1024)
    dex = A.Dex(packed, "packed.dex")
    check("识别为壳 DEX", dex.looks_packed, dex.data_end)
    check("算出密文大小", dex.packed_bytes > 90 * 1024, dex.packed_bytes)

    # 正常 DEX：data 铺满整个文件
    normal = bytearray(build_dex(4096))
    struct.pack_into("<I", normal, 0x68, len(normal) - 112)
    n = A.Dex(bytes(normal), "normal.dex")
    check("正常 DEX 不误判", not n.looks_packed, n.data_end)

    # 非 DEX 要报错而不是瞎解
    try:
        A.Dex(b"NOTDEX!!", "x")
        check("非 DEX 报错", False)
    except ValueError:
        check("非 DEX 报错", True)


# --------------------------------------------------------------------------
# 4. 明文雕刻
# --------------------------------------------------------------------------


def test_carve():
    print("[4] 明文雕刻")
    blob = (
        b"\x00\x01\x02Lcom/newskyer/draw/MainActivity;\x00"
        b"Landroidx/compose/ui/Modifier;\x00"
        b"https://user.cicoe.net:29091/xzbj/app/v1\x00"
        b"some printable string here\x00"
    )
    classes, urls, strings = A.carve(blob)
    check("捞到 2 个类", len(classes) == 2, classes)
    check("类名正确", "Lcom/newskyer/draw/MainActivity;" in classes, classes)
    check("捞到 URL", "https://user.cicoe.net:29091/xzbj/app/v1" in urls, urls)
    check("捞到字符串", any("printable" in s for s in strings), strings[:3])

    tree = A.package_tree(classes)
    check("包聚合正确", tree.get("com/newskyer") == 1, dict(tree))


# --------------------------------------------------------------------------
# 5. 加固特征识别
# --------------------------------------------------------------------------


def test_packer_detect():
    print("[5] 加固特征识别")
    names = ["classes.dex", "lib/arm64-v8a/libijiami_1011.so",
             "assets/ijiami_1011.VData"]
    hits = A.detect_packer(names, lambda n, l: b"")
    check("识别出爱加密", any(h["packer"].startswith("爱加密") for h in hits),
          [h["packer"] for h in hits])

    hits2 = A.detect_packer(["classes.dex", "lib/arm64-v8a/libjiagu.so"],
                            lambda n, l: b"")
    check("识别出 360", any("360" in h["packer"] for h in hits2),
          [h["packer"] for h in hits2])

    hits3 = A.detect_packer(["classes.dex"], lambda n, l: b"")
    check("普通 APK 不误判", hits3 == [], hits3)


# --------------------------------------------------------------------------
# 6. AXML（用真实 Manfiest 的分片结构）
# --------------------------------------------------------------------------


def test_axml_rejects_garbage():
    print("[6] AXML 容错")
    try:
        A.AXML(b"\x00\x00\x00\x00" * 16)
        check("垃圾数据报错", False)
    except Exception:
        check("垃圾数据报错", True)


# --------------------------------------------------------------------------
# 7. 端到端：造一个迷你 APK 跑完整流程
# --------------------------------------------------------------------------


def test_end_to_end():
    print("[7] 端到端（合成迷你 APK）")
    tmp = tempfile.mkdtemp()
    apk = os.path.join(tmp, "mini.apk")
    dex = build_dex(payload_size=2048)
    # 往 dex 的"密文区"塞一点明文残留
    dex = bytearray(dex)
    marker = b"Lcom/demo/app/Foo;\x00https://demo.example.com/api\x00"
    dex[112 + 4096:112 + 4096 + len(marker)] = marker

    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", bytes(dex))
        z.writestr("lib/arm64-v8a/libijiami_x.so", b"\x7fELF")
        z.writestr("assets/ijiami_x.VData", b"ivmp\n02\x00")

    out = os.path.join(tmp, "out")
    data = A.analyze(apk, out, want_json=True)

    check("识别出爱加密", any(h["packer"].startswith("爱加密")
                        for h in data.get("packers", [])),
          [h.get("packer") for h in data.get("packers", [])])
    check("雕刻出类", data.get("class_count", 0) >= 1, data.get("class_count"))
    check("雕刻出 URL", data.get("url_count", 0) >= 1, data.get("url_count"))
    check("生成了 report.txt", os.path.exists(os.path.join(out, "report.txt")))
    check("生成了 report.json", os.path.exists(os.path.join(out, "report.json")))
    check("生成了 classes_carved.txt",
          os.path.exists(os.path.join(out, "classes_carved.txt")))


def main():
    print("=" * 60)
    print("packed-apk-analyzer 自测")
    print("=" * 60)
    test_string_pool()
    test_ijiami()
    test_dex()
    test_carve()
    test_packer_detect()
    test_axml_rejects_garbage()
    test_end_to_end()
    print("=" * 60)
    if FAILED:
        print("失败 %d 项：%s" % (len(FAILED), ", ".join(FAILED)))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
