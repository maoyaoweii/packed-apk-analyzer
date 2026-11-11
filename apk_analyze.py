#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
packed-apk-analyzer —— 加固 APK 静态分析工具（零第三方依赖）

专治"装了壳、jadx 只能反编译出几十个类"的 APK。
不脱壳也能把里面的东西尽量挖干净：

    1. ZIP 结构盘点 + 加固特征识别（爱加密 / 360 / 腾讯乐固 / 百度 / 阿里）
    2. 二进制 AndroidManifest.xml 解析 → 包名、版本、权限、四大组件
    3. resources.arsc 字符串池解析 → 全部界面文案（含中文）
    4. DEX 结构分析 → 判断"这是不是壳"（真 header + 加密体）
    5. 明文雕刻 → 从加密数据流里捞出类描述符 / URL / 字符串
    6. 壳的字符串混淆还原（内置爱加密 Base64+Netease 循环异或）

用法：
    python apk_analyze.py app.apk              # 输出到 ./out
    python apk_analyze.py app.apk result_dir   # 指定输出目录
    python apk_analyze.py app.apk out --json   # 额外输出 report.json

设计原则：
    * 只做静态读取，不运行 APK，不发任何网络请求
    * 全程流式处理，几十 MB 的 DEX 也不会把内存吃满
    * 每一层失败都不影响其它层，能挖多少算多少

作者：DSH 会话产出，2026-11
许可：MIT
"""

import base64
import collections
import json
import math
import os
import re
import struct
import sys
import zipfile

VERSION = "1.1.0"

# ==========================================================================
# 0. 基础工具
# ==========================================================================


def u16(b, o):
    """读 16 位小端无符号整数。"""
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    """读 32 位小端无符号整数。"""
    return struct.unpack_from("<I", b, o)[0]


def uleb128(b, o):
    """读 DEX 的变长整数，返回 (值, 新偏移)。最多 5 字节。"""
    result = 0
    shift = 0
    for _ in range(5):
        byte = b[o]
        o += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return result, o


def entropy(buf):
    """香农熵。>7.5 基本就是加密或压缩数据，<6 多半是代码或文本。"""
    if not buf:
        return 0.0
    counter = collections.Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in counter.values())


# ==========================================================================
# 1. 加固特征库
# ==========================================================================

# 每条：(壳名, [(匹配位置, 匹配串), ...], 说明)
# 匹配位置："path" 匹配 ZIP 条目名，"value" 匹配条目内容里的字符串
PACKER_SIGNATURES = [
    ("爱加密 iJiami", [
        ("path", "ijiami"),
        ("path", ".VData"),
        ("path", "libijiami"),
        ("path", "libexecmain"),
        ("path", ".nesec_patch"),
    ], "assets/ijiami_*.VData + libijiami_*.so，dex 头部保留但数据段加密"),
    ("360 加固", [
        ("path", "libjiagu"),
        ("path", "libprotectClass"),
        ("value", "com.stub.StubApp"),
        ("value", "StubApp"),
    ], "libjiagu*.so + com.stub.StubApp 入口"),
    ("腾讯乐固 Legu", [
        ("path", "libshella"),
        ("path", "libshellx"),
        ("path", "0OO00l111l1l"),
        ("path", "tosversion"),
        ("value", "com.tencent.StubShell"),
    ], "libshella*.so + 数字命名的 dex 分片"),
    ("百度加固", [
        ("path", "libbaiduprotect"),
        ("value", "com.baidu.protect"),
    ], "libbaiduprotect.so"),
    ("阿里聚安全", [
        ("path", "libmobisec"),
        ("path", "aliprotect"),
        ("value", "com.ali.mobisecenhance"),
    ], "libmobisec.so / aliprotect.dat"),
    ("梆梆", [
        ("path", "libsecexe"),
        ("path", "libsecmain"),
        ("path", "libDexHelper"),
    ], "libsecexe.so + libsecmain.so"),
    ("网易易盾", [
        ("path", "libnesec"),
        ("value", "com.netease.nis"),
    ], "libnesec.so"),
    ("顶象", [
        ("path", "libx3g"),
        ("value", "com.dingxiang.mobi"),
    ], "libx3g.so"),
]


def detect_packer(names, sample_reader):
    """
    识别用了哪家加固。

    names         : ZIP 条目名列表
    sample_reader : 函数，接收条目名返回前若干 KB 内容（找不到返回 b""）
    """
    lowered = [n.lower() for n in names]
    hits = []
    for packer, sigs, note in PACKER_SIGNATURES:
        evidence = []
        for kind, pat in sigs:
            if kind == "path":
                matched = [n for n, low in zip(names, lowered) if pat.lower() in low]
                if matched:
                    evidence.append("%s -> %s" % (pat, matched[0]))
            else:
                for n in ("classes.dex", "AndroidManifest.xml"):
                    blob = sample_reader(n, 4 * 1024 * 1024)
                    if pat.encode() in blob:
                        evidence.append("%s in %s" % (pat, n))
                        break
        if evidence:
            hits.append({"packer": packer, "evidence": evidence, "note": note})
    return hits


# ==========================================================================
# 2. 二进制 XML（AXML）解析
# ==========================================================================

# 单条字符串的合理上限。arsc 里最长的通常是隐私政策正文，
# 设 64 KB 足够；再长就说明偏移算错了，是垃圾数据。
MAX_STRING_BYTES = 64 * 1024

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


def parse_string_pool(d, pos):
    """
    解析 RES_STRING_POOL_CHUNK。

    AXML 和 resources.arsc 用的是同一套字符串池格式，所以这个函数两边共用。

    结构：
        header(28)  : type/size | headerSize/size | count | styleCount | flags
                      | stringsStart | stylesStart
        offsets     : count 个 uint32，相对字符串数据区起点的偏移
        data        : 每个字符串 = [uleb128 字符数][uleb128 字节数][UTF-8 字节]
                      或者 = [uint16 长度][UTF-16LE 字节]
    """
    count = u32(d, pos + 8)
    flags = u32(d, pos + 16)
    strings_start = u32(d, pos + 20)
    is_utf8 = bool(flags & 0x100)
    base = pos + 28
    data_base = pos + strings_start
    if base + count * 4 > len(d):
        return []
    offsets = struct.unpack_from("<%dI" % count, d, base)
    out = []
    for off in offsets:
        o = data_base + off
        try:
            if is_utf8:
                _, o = uleb128(d, o)                   # 字符数，用不上
                blen, o = uleb128(d, o)                # 字节数
                if blen > MAX_STRING_BYTES or o + blen > len(d):
                    raise ValueError                       # 坏偏移，别信
                out.append(d[o:o + blen].decode("utf-8", "replace"))
            else:
                n = u16(d, o)
                o += 2
                if n > MAX_STRING_BYTES // 2 or o + n * 2 > len(d):
                    raise ValueError
                out.append(d[o:o + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


class AXML:
    """把 AndroidManifest.xml 的二进制 XML 解析成元素列表。"""

    def __init__(self, data):
        if u16(data, 0) != RES_XML_TYPE:
            raise ValueError("不是 AXML（magic 0x%04x）" % u16(data, 0))
        self.data = data
        self.strings = []
        self.elements = []       # [(tag, {attr: value})]
        self._walk()

    def _walk(self):
        d = self.data
        pos = u16(d, 2)          # header size，通常 8
        while pos + 8 <= len(d):
            ctype = u16(d, pos)
            chs = u16(d, pos + 2)
            csz = u32(d, pos + 4)
            if csz <= 0 or pos + csz > len(d):
                break
            if ctype == RES_STRING_POOL_TYPE:
                self.strings = parse_string_pool(d, pos)
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                self._start_element(pos, chs)
            pos += csz

    def _start_element(self, pos, chs):
        d = self.data
        name_idx = u32(d, pos + 20)
        attr_start = u16(d, pos + 24)
        attr_size = u16(d, pos + 26)
        attr_count = u16(d, pos + 28)
        if attr_size == 0:
            attr_size = 20
        tag = self._s(name_idx)
        attrs = {}
        base = pos + chs + attr_start
        for i in range(attr_count):
            o = base + i * attr_size
            if o + 20 > len(d):
                break
            a_name = u32(d, o + 4)
            a_raw = u32(d, o + 8)
            a_type = d[o + 15]
            a_data = u32(d, o + 16)
            key = self._s(a_name)
            if a_type == TYPE_STRING:
                val = self._s(a_data)
            elif a_type == TYPE_INT_DEC:
                val = str(struct.unpack("<i", struct.pack("<I", a_data))[0])
            elif a_type == TYPE_INT_HEX:
                val = "0x%x" % a_data
            elif a_type == TYPE_INT_BOOLEAN:
                val = "true" if a_data else "false"
            elif a_type == TYPE_REFERENCE:
                val = "@ref/0x%08x" % a_data
            else:
                val = self._s(a_raw) if a_raw != 0xFFFFFFFF else str(a_data)
            attrs[key] = val
        self.elements.append((tag, attrs))

    def _s(self, idx):
        if idx == 0xFFFFFFFF or idx >= len(self.strings):
            return ""
        return self.strings[idx]

    # ---- 便捷查询 ----
    def tags(self, tag):
        return [a for t, a in self.elements if t == tag]

    def manifest_info(self):
        """抽出最有用的 manifest 信息。"""
        info = {}
        m = self.tags("manifest")
        if m:
            a = m[0]
            for key in ("package", "versionName", "versionCode",
                        "compileSdkVersion", "compileSdkVersionCodename",
                        "platformBuildVersionCode", "sharedUserId"):
                if key in a:
                    info[key] = a[key]
        app = self.tags("application")
        if app:
            a = app[0]
            for key in ("name", "label", "icon", "debuggable", "allowBackup",
                        "usesCleartextTraffic", "networkSecurityConfig",
                        "appComponentFactory", "extractNativeLibs"):
                if key in a:
                    info["application." + key] = a[key]
        info["permissions"] = sorted({a.get("name", "")
                                      for a in self.tags("uses-permission")
                                      if a.get("name")})
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            names = [a.get("name", "") for a in self.tags(tag) if a.get("name")]
            if names:
                info[tag + "s"] = sorted(set(names))
        # 权限里比较危险的那批
        dangerous = {
            "MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
            "SYSTEM_ALERT_WINDOW", "PROJECT_MEDIA", "RECORD_AUDIO", "CAMERA",
            "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "GET_TASKS", "DUMP", "READ_SMS", "SEND_SMS", "READ_CONTACTS",
        }
        info["dangerous_permissions"] = sorted(
            p for p in info["permissions"]
            if p.rsplit(".", 1)[-1] in dangerous or p.endswith("MANAGE_EXTERNAL_STORAGE"))
        return info


# ==========================================================================
# 3. resources.arsc 字符串池
# ==========================================================================


def arsc_strings(data):
    """arsc 的全局字符串池永远是第一个 chunk 之后的那块。"""
    pos = u16(data, 2)
    while pos + 8 <= len(data):
        ctype = u16(data, pos)
        csz = u32(data, pos + 4)
        if csz <= 0:
            break
        if ctype == RES_STRING_POOL_TYPE:
            return parse_string_pool(data, pos)
        pos += csz
    return []


# ==========================================================================
# 4. DEX 结构分析
# ==========================================================================


class Dex:
    """
    只读 DEX header / string_ids / class_defs，不碰方法体。

    关键点：判断一个 DEX 是不是"壳"，看 header 声明的数据区能不能铺满整个文件。
    正常 DEX：data_off + data_size ≈ 文件长度
    装壳后：前面一小段是真数据，后面挂着一大坨加密内容，两者差很多
    """

    def __init__(self, data, name="classes.dex"):
        if data[:4] != b"dex\n":
            raise ValueError("%s 不是 DEX" % name)
        self.data = data
        self.name = name
        self.magic = data[:8].rstrip(b"\x00")
        self.file_size = u32(data, 0x20)
        self.header_size = u32(data, 0x24)
        self.endian_tag = u32(data, 0x28)
        self.map_off = u32(data, 0x34)
        self.string_ids_size = u32(data, 0x38)
        self.string_ids_off = u32(data, 0x3C)
        self.type_ids_size = u32(data, 0x40)
        self.type_ids_off = u32(data, 0x44)
        self.method_ids_size = u32(data, 0x58)
        self.method_ids_off = u32(data, 0x5C)
        self.class_defs_size = u32(data, 0x60)
        self.class_defs_off = u32(data, 0x64)
        self.data_size = u32(data, 0x68)
        self.data_off = u32(data, 0x6C)

    # ---- 判定 ----
    @property
    def data_end(self):
        return self.data_off + self.data_size

    @property
    def packed_bytes(self):
        """header 之后、没有被数据区覆盖的字节数——基本就是加密载荷。"""
        return max(0, len(self.data) - self.data_end)

    @property
    def looks_packed(self):
        return self.data_end < len(self.data) * 0.95

    # ---- 读取 ----
    def string_at(self, idx):
        off = u32(self.data, self.string_ids_off + idx * 4)
        n, p = uleb128(self.data, off)
        return self.data[p:p + n].decode("utf-8", "replace")

    def class_names(self):
        """遍历 class_defs 拿类名。class_def.class_idx 是 type_ids 的下标。"""
        out = []
        for i in range(self.class_defs_size):
            o = self.class_defs_off + i * 32
            if o + 32 > len(self.data):
                break
            class_idx = u32(self.data, o)
            str_idx = u32(self.data, self.type_ids_off + class_idx * 4)
            out.append(self.string_at(str_idx))
        return out

    def all_strings(self):
        return [self.string_at(i) for i in range(self.string_ids_size)]

    def report(self):
        lines = [
            ("文件", "%s (%.1f MB)" % (self.name, len(self.data) / 1048576)),
            ("magic", repr(self.magic.decode("latin1"))),
            ("header 声明 file_size", self.file_size),
            ("实际文件长度", len(self.data)),
            ("string_ids", "%d 条 @0x%x" % (self.string_ids_size, self.string_ids_off)),
            ("type_ids", "%d 条" % self.type_ids_size),
            ("method_ids", "%d 条" % self.method_ids_size),
            ("class_defs", "%d 个 @0x%x" % (self.class_defs_size, self.class_defs_off)),
            ("data 区间", "0x%x ~ 0x%x (%d 字节)" % (self.data_off, self.data_end, self.data_size)),
        ]
        if self.looks_packed:
            lines.append(("", ""))
            lines.append(("结论", "【加固壳 DEX】"))
            lines.append(("原因", "真实数据只到 0x%x，之后还有 %.1f MB 是密文"
                          % (self.data_end, self.packed_bytes / 1048576)))
        else:
            lines.append(("结论", "结构完整，正常 DEX"))
        return lines


# ==========================================================================
# 5. 明文雕刻
# ==========================================================================

RE_CLASS = re.compile(rb"L(?:com|org|net|androidx|kotlin|io|cn|javax|dalvik|"
                      rb"java|de|uk|me|tv|xyz)/[A-Za-z0-9_$/\-]{2,150};")
RE_URL = re.compile(rb"https?://[\x21-\x7e]{6,200}")
RE_PRINTABLE = re.compile(rb"[\x20-\x7e]{8,300}")


def carve(data):
    """
    从（可能加密的）数据流里雕刻明文。

    原理：加固工具通常只加密"代码段"，而 DEX 里的
        - 类描述符（Lcom/xxx/Yyy;）
        - 字符串常量（URL、Toast 文案、字段名）
    常常以明文残留。直接对整块二进制做正则，就能把类结构和文案捞出来。
    这比脱壳便宜得多，信息量却能达到脱壳的 70%。
    """
    classes = sorted({m.group().decode("utf-8", "replace")
                      for m in RE_CLASS.finditer(data)})
    urls = sorted({m.group().decode("utf-8", "replace")
                   for m in RE_URL.finditer(data)})
    strings = sorted({m.group().decode("utf-8", "replace")
                      for m in RE_PRINTABLE.finditer(data)})
    return classes, urls, strings


def package_tree(classes, depth=2):
    """把类名按包聚合，用来看模块划分。"""
    counter = collections.Counter()
    for c in classes:
        body = c[1:-1] if c.startswith("L") and c.endswith(";") else c
        parts = body.split("/")
        if len(parts) >= depth:
            counter["/".join(parts[:depth])] += 1
    return counter


# ==========================================================================
# 6. 壳的字符串混淆还原
# ==========================================================================

# ---- 爱加密：Base64 解码后与固定密钥循环异或 ----
# 推导：拿一条已知明文（如壳的 Application 类名）与密文等长异或，
#       得到的 37 字节正好是 "NeteaseNeteaseNetease..." 循环 → 密钥 = b"Netease"
IJIAMI_KEY = b"Netease"


def ijiami_decode(cipher_text):
    s = cipher_text.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s)
    except Exception:
        return None
    return bytes(b ^ IJIAMI_KEY[i % len(IJIAMI_KEY)]
                 for i, b in enumerate(raw)).decode("utf-8", "replace")


def looks_like_real_string(s):
    """
    过滤解密噪音。

    字符串池里混着 "VDDDDDDDDD"（方法签名短码）、"CCCC" 这类合法常量，
    拿它们当密文解出来必然是乱码，所以要过三道筛：
        1. 必须是合法 UTF-8（没有替换符）
        2. 必须含字母 / 数字 / 汉字
        3. 可打印字符占比 > 95%
    """
    if not s or len(s) < 2 or "\ufffd" in s:
        return False
    if not any(c.isalnum() or "\u4e00" <= c <= "\u9fff" for c in s):
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return printable / len(s) > 0.95


def decode_ijiami_strings(dex):
    """
    遍历 DEX 字符串池，把每条都当密文试解一次。

    为什么不在整个文件里搜 a.auu.a.c("...")？
    因为加固后调用指令本身被加密了，只剩字符串池里的密文还留在明面上，
    所以必须从 string_ids 表出发。
    """
    found = {}
    for i in range(dex.string_ids_size):
        try:
            s = dex.string_at(i)
        except Exception:
            continue
        if not (4 <= len(s) <= 512):
            continue
        plain = ijiami_decode(s)
        if plain and looks_like_real_string(plain) and plain != s:
            found[s] = plain
    return found


# ==========================================================================
# 7. 主流程
# ==========================================================================


class Report:
    def __init__(self):
        self.lines = []
        self.data = {}

    def say(self, s=""):
        self.lines.append(str(s))
        print(s, flush=True)

    def head(self, s):
        self.say("")
        self.say("─" * 76)
        self.say("【%s】" % s)

    def kv(self, k, v, width=22):
        self.say("    %-*s %s" % (width, k, v))


def analyze(apk_path, out_dir="out", want_json=False):
    os.makedirs(out_dir, exist_ok=True)
    r = Report()

    def dump(name, text):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        r.say("    → %s" % path)
        return path

    r.say("=" * 76)
    r.say(" 加固 APK 静态分析  v%s" % VERSION)
    r.say(" 目标：%s" % apk_path)
    r.say("=" * 76)

    z = zipfile.ZipFile(apk_path)
    infos = z.infolist()
    names = [i.filename for i in infos]

    cache = {}

    def sample(name, limit):
        if name not in cache:
            try:
                with z.open(name) as f:
                    cache[name] = f.read(limit)
            except Exception:
                cache[name] = b""
        return cache[name][:limit]

    # ---------------- 1. 概览 ----------------
    r.head("1. 文件概览")
    total = os.path.getsize(apk_path)
    r.kv("文件大小", "%.1f MB / %d 个条目" % (total / 1048576, len(infos)))
    dexes = [i for i in infos if i.filename.endswith(".dex")]
    for d in dexes:
        r.kv("DEX", "%8.1f MB  %s" % (d.file_size / 1048576, d.filename))
    abis = collections.Counter(n.split("/")[1] for n in names if n.startswith("lib/"))
    if abis:
        r.kv("so 架构", ", ".join("%s(%d)" % (k, v) for k, v in abis.items()))
    r.say("    最大的 12 个文件：")
    for i in sorted(infos, key=lambda x: x.file_size, reverse=True)[:12]:
        r.say("      %8.1f MB  %s" % (i.file_size / 1048576, i.filename))

    # ---------------- 2. 加固识别 ----------------
    r.head("2. 加固特征")
    packs = detect_packer(names, sample)
    if packs:
        for p in packs:
            r.say("    ★ %s" % p["packer"])
            r.say("      常理：%s" % p["note"])
            for e in p["evidence"]:
                r.say("      证据：%s" % e)
    else:
        r.say("    未命中已知加固特征（可能是普通 APK，或用了没收录的壳）")
    r.data["packers"] = packs

    # ---------------- 3. Manifest ----------------
    r.head("3. AndroidManifest.xml")
    manifest_info = {}
    try:
        ax = AXML(z.read("AndroidManifest.xml"))
        manifest_info = ax.manifest_info()
        for k, v in manifest_info.items():
            if isinstance(v, list):
                r.kv(k, "%d 项" % len(v))
            else:
                r.kv(k, v)
        if manifest_info.get("dangerous_permissions"):
            r.say("")
            r.say("    高危权限（%d 条）：" % len(manifest_info["dangerous_permissions"]))
            for p in manifest_info["dangerous_permissions"]:
                r.say("      ! " + p)
        dump("manifest_strings.txt", "\n".join(ax.strings))
    except Exception as e:
        r.say("    解析失败：%s" % e)
    r.data["manifest"] = manifest_info

    # ---------------- 4. 资源字符串 ----------------
    r.head("4. resources.arsc 字符串")
    try:
        arsc = arsc_strings(z.read("resources.arsc"))
        cn = [s for s in arsc
              if any("\u4e00" <= c <= "\u9fff" for c in s) and len(s.strip()) >= 2]
        r.kv("字符串总数", len(arsc))
        r.kv("含中文", len(cn))
        dump("arsc_strings.txt",
             "\n".join("%d\t%s" % (i, s.replace("\x00", ""))
                       for i, s in enumerate(arsc)))
        dump("arsc_chinese.txt", "\n".join(dict.fromkeys(cn)))
        r.data["arsc_count"] = len(arsc)
        r.data["arsc_chinese"] = len(cn)
    except Exception as e:
        r.say("    解析失败：%s" % e)

    # ---------------- 5. DEX ----------------
    all_classes, all_urls = [], []
    for d in dexes:
        r.head("5. DEX 分析：%s" % d.filename)
        raw = z.read(d.filename)
        try:
            dex = Dex(raw, d.filename)
        except Exception as e:
            r.say("    不是合法 DEX：%s" % e)
            continue
        for k, v in dex.report():
            if k:
                r.kv(k, v)

        if dex.looks_packed:
            r.say("")
            r.say("    分段熵（>7.5 ≈ 加密/压缩，<6 ≈ 代码/文本）：")
            step = max(1, len(raw) // 14)
            for off in range(0, len(raw), step):
                chunk = raw[off:off + 65536]
                bar = "█" * int(entropy(chunk) * 4)
                r.say("      0x%08x  H=%.2f  %s" % (off, entropy(chunk), bar))

        r.say("")
        r.say("    DEX 里声明的真实类（%d 个）：" % dex.class_defs_size)
        try:
            real = dex.class_names()
            for n in real[:60]:
                r.say("      " + n)
            if len(real) > 60:
                r.say("      ...（其余 %d 个见 classes_real.txt）" % (len(real) - 60))
            dump("classes_real.txt", "\n".join(real))
        except Exception as e:
            r.say("      class_defs 读取失败：%s" % e)

        # ---- 雕刻 ----
        r.say("")
        r.say("    从数据流里雕刻明文：")
        classes, urls, strings = carve(raw)
        all_classes += classes
        all_urls += urls
        r.kv("类描述符", len(classes))
        r.kv("URL", len(urls))
        r.kv("可打印字符串", len(strings))
        tree = package_tree(classes)
        r.say("    顶层包（类数前 20）：")
        for k, v in tree.most_common(20):
            r.say("      %6d  %s" % (v, k))
        dump("classes_carved.txt", "\n".join(classes))
        dump("urls.txt", "\n".join(urls))
        dump("strings_carved.txt", "\n".join(strings))

        # ---- 壳字符串 ----
        r.say("")
        r.say("    壳的字符串混淆还原（爱加密：Base64 + b\"Netease\" 循环异或）")
        table = decode_ijiami_strings(dex)
        r.kv("还原成功", "%d 条" % len(table))
        if table:
            for cipher, plain in list(sorted(table.items(), key=lambda kv: kv[1]))[:30]:
                r.say("      %-62s ⇐ %s" % (plain.replace("\n", "\\n"), cipher))
            dump("ijiami_decoded.txt",
                 "\n".join("%s\t%s" % (plain, cipher)
                           for cipher, plain in sorted(table.items(),
                                                       key=lambda kv: kv[1])))
        r.data["ijiami_decoded"] = len(table)

    # ---------------- 6. 汇总 ----------------
    r.head("6. 汇总")
    r.kv("类描述符总数", len(set(all_classes)))
    r.kv("URL 总数", len(set(all_urls)))
    if all_urls:
        hosts = collections.Counter()
        for u in set(all_urls):
            m = re.match(r"https?://([^/:]+)", u)
            if m:
                hosts[m.group(1)] += 1
        r.say("")
        r.say("    域名分布（前 25）：")
        for h, c in hosts.most_common(25):
            r.say("      %5d  %s" % (c, h))
        r.data["hosts"] = dict(hosts.most_common(100))

    r.data["class_count"] = len(set(all_classes))
    r.data["url_count"] = len(set(all_urls))

    dump("report.txt", "\n".join(r.lines))
    if want_json:
        with open(os.path.join(out_dir, "report.json"), "w",
                  encoding="utf-8") as f:
            json.dump(r.data, f, ensure_ascii=False, indent=2)
        r.say("    → %s" % os.path.join(out_dir, "report.json"))
    r.say("")
    r.say("完成。所有产物在 %s" % os.path.abspath(out_dir))
    return r.data


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        print(__doc__)
        sys.exit(1)
    analyze(args[0], args[1] if len(args) > 1 else "out",
            want_json="--json" in flags)


if __name__ == "__main__":
    main()
