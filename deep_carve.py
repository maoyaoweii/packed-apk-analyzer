#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deep_carve.py —— 从加固 DEX 的"打散数据区"里系统性还原 DEX 字符串池与代码结构

背景
----
爱加密这类壳会把真实 DEX 拆散、按自定义格式重排到 classes.dex 的数据区，
但**不会抹掉 DEX 的 string_data 单元本身**。string_data 的格式是：

    [uleb128 长度][UTF-8 字节][\\x00]

真实 DEX 的字符串池是成千上万个这种单元**连续排列**的。所以只要找到
"连续 N 个都能按 string_data 解析成功"的区间，就能把完整字符串池挖出来，
而不是像正则雕刻那样碰运气。

本脚本做四件事：
    1. 扫描整个 classes.dex，用"连续命中"判定真实字符串池区并提取全部字符串
    2. 把字符串按 DEX 语义分类（类描述符 / 成员 / 签名 / 业务文案 / URL / 资源）
    3. 给类描述符做功能模块归类，生成源码地图
    4. 输出可用于后续反编译/重建的清单

全程分块读取，不会把 100MB 一次性摊成多个大对象。

用法：
    python deep_carve.py <classes.dex> [输出目录]
"""

import collections
import json
import os
import re
import struct
import sys

# ---- DEX string_data 长度上限：正常字符串不会超过 64KB ----
MAX_STR = 64 * 1024
# 连续多少个合法 string_data 才认定是真实字符串池区
RUN_THRESHOLD = 6


def uleb(b, o, end):
    """读 uleb128，越界返回 None。"""
    r = 0
    s = 0
    for _ in range(5):
        if o >= end:
            return None
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return (r, o)
    return None


def parse_string_data(b, o, end):
    """
    尝试在 o 处解析一个 DEX string_data 单元。
    返回 (字符串, 新偏移) 或 None。
    """
    v = uleb(b, o, end)
    if v is None:
        return None
    n, p = v
    if n <= 0 or n > MAX_STR or p + n >= end:
        return None
    if b[p + n] != 0:                      # 必须以 \x00 结尾
        return None
    raw = b[p:p + n]
    # DEX 用 MUTF-8，绝大多数就是 UTF-8；控制字符不算有效文本
    if any(c < 0x09 for c in raw):
        return None
    try:
        s = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if not s.isprintable() and "\n" not in s and "\t" not in s:
        return None
    return (s, p + n + 1)


def carve_string_pools(data):
    """
    扫描整块数据，找出所有"连续 >=RUN_THRESHOLD 个 string_data"的区间，
    把里面的字符串全部收进集合。

    返回 (strings集合, 区间列表)。
    """
    n = len(data)
    strings = set()
    regions = []
    i = 0
    while i < n - 16:
        # 快速起步：先试第一个单元
        first = parse_string_data(data, i, n)
        if first is None:
            i += 1
            continue
        # 连续解析
        run = []
        o = i
        while o < n - 4:
            r = parse_string_data(data, o, n)
            if r is None:
                break
            s, o2 = r
            run.append(s)
            o = o2
            if len(run) > 200000:            # 保险丝
                break
        if len(run) >= RUN_THRESHOLD:
            for s in run:
                strings.add(s)
            regions.append((i, o, len(run)))
            i = o
        else:
            i += 1
    return strings, regions


def classify_string(s, class_re, url_re):
    """给单条字符串做 DEX 语义分类。"""
    if s.startswith("L") and s.endswith(";") and "/" in s and " " not in s:
        return "class"
    if s.startswith("(") and ")" in s:
        return "proto"                       # 方法签名 (... )...
    if url_re.match(s):
        return "url"
    if s.startswith(("Landroid", "Ljava", "Lkotlin", "Lkotlinx", "Ldalvik")):
        return "class"
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", s):
        return "member"                       # 字段名 / 方法名 / 短常量
    if re.fullmatch(r"\[*[BCDFIJSZV]", s) or s.startswith("["):
        return "type"
    if any("\u4e00" <= c <= "\u9fff" for c in s):
        return "text_zh"
    if s.startswith(("@", "res/", "android:", "http")):
        return "resource"
    return "other"


# ---- 功能模块分类规则：按包名前缀落到功能域 ----
MODULE_RULES = [
    # (功能域, [包名关键词])
    ("笔记画布/手写内核", ["com/newskyer/paint", "/brush", "/layer", "/penbox",
                     "/sticker", "/hvtoolbar", "/draw_", "PaintView"]),
    ("笔记业务/文件管理", ["com/newskyer/draw/file", "/notetree", "/note_navigation",
                      "/folderDevice", "/catalog", "/richText", "/template", "/tab"]),
    ("OCR/扫描/截屏", ["/doc_scan", "/capture", "/ocr", "/asr", "/sensors",
                   "/floatBall/eyecase", "ColorSnap"]),
    ("思维导图", ["/mindmapextension", "/mindmap"]),
    ("闪卡/背诵", ["/flashCards"]),
    ("录音/语音", ["/record", "/asr", "sherpa", "voice"]),
    ("PDF/文档", ["/pdf", "itext", "/cropper", "/crop", "/videoextension"]),
    ("云同步/传输", ["/cloud", "/baidusync", "/transfers", "/webfile", "/webexcerpt",
                 "/email", "qiniu", "/net/", "websocket", "dropbox"]),
    ("账号/登录/支付", ["/user", "/pay", "/login", "cicoe/user", "/vip", "billing"]),
    ("悬浮窗/浮球助手", ["/floatBall", "/float_windows", "/dynamicmenu"]),
    ("广告SDK-穿山甲", ["com/byazt", "com/bytedance", "com/ss/android"]),
    ("广告SDK-快手", ["com/kwad", "com/kwai"]),
    ("广告SDK-腾讯优量汇", ["com/qq/e", "gdt"]),
    ("广告SDK-百度", ["com/baidu", "bdxadsdk"]),
    ("广告SDK-华为/荣耀", ["com/huawei", "com/hihonor"]),
    ("广告SDK-小米Mimo", ["com/miui", "mimo"]),
    ("广告SDK-OPPO/vivo", ["com/opos", "com/heytap"]),
    ("广告SDK-京东/其他", ["com/jd", "com/yfanads", "com/byazt"]),
    ("推送/统计", ["umeng", "sensorsdata", "bugly", "xcrash", "push", "analytics",
                "hianalytics", "crash"]),
    ("华为HMS/Google服务", ["com/huawei/hms", "com/google/android/gms",
                       "com/google/firebase", "agconnect"]),
    ("Jetpack Compose UI", ["androidx/compose"]),
    ("AndroidX 基础库", ["androidx/core", "androidx/appcompat", "androidx/room",
                     "androidx/lifecycle", "androidx/camera", "androidx/media3",
                     "androidx/recyclerview", "androidx/constraintlayout",
                     "androidx/fragment", "androidx/work"]),
    ("网络库", ["okhttp", "retrofit", "ktor", "volley", "http"]),
    ("加密/安全", ["bouncycastle", "spongycastle", "conscrypt", "crypto", "tink"]),
    ("图片加载", ["glide", "picasso", "coil", "fresco", "bumptech"]),
    ("序列化", ["gson", "fastjson", "jackson", "protobuf", "moshi"]),
    ("Kotlin运行时", ["kotlin/", "kotlinx/"]),
    ("AI/推理框架", ["onnx", "ncnn", "paddle", "tflite", "opencv", "hiai",
                  "sherpa", "openblas", "kaldi"]),
    ("其他第三方", ["org/", "io/", "net/", "com/amazonaws", "com/itextpdf",
                 "/zxing", "/upnp", "apache"]),
]


def classify_module(cls):
    """把类描述符归到功能域。返回 (功能域, 二级包名)。"""
    body = cls[1:-1] if cls.startswith("L") and cls.endswith(";") else cls
    parts = body.split("/")
    second = "/".join(parts[:2]) if len(parts) >= 2 else body
    for name, keys in MODULE_RULES:
        for k in keys:
            if k.strip("/") in body:
                return name, second
    # 没命中规则时按顶层包兜底
    top = parts[0] if parts else body
    fallback = {
        "com": "其他业务/未归类", "org": "其他第三方", "androidx": "AndroidX 基础库",
        "kotlin": "Kotlin运行时", "kotlinx": "Kotlin运行时", "net": "其他第三方",
        "io": "其他第三方", "javax": "Java标准库", "java": "Java标准库",
        "dalvik": "Dalvik运行时",
    }
    return fallback.get(top, "其他业务/未归类"), second


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    dex_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "deep_out"
    os.makedirs(out_dir, exist_ok=True)

    size = os.path.getsize(dex_path)
    print("读取 %s (%.1f MB) ..." % (dex_path, size / 1048576))
    with open(dex_path, "rb") as f:
        data = f.read()
    print("已载入。开始扫描 DEX string_data 单元 ...")

    strings, regions = carve_string_pools(data)
    print("识别到 %d 个连续字符串池区，共 %d 条唯一字符串" % (len(regions), len(strings)))
    total_region_bytes = sum(b - a for a, b, _ in regions)
    print("字符串池区总覆盖 %.1f MB" % (total_region_bytes / 1048576))

    # ---- 分类字符串 ----
    CRE = re.compile(r"^L[\w/$\-]+;$")
    URE = re.compile(r"^https?://")
    buckets = collections.defaultdict(list)
    for s in strings:
        buckets[classify_string(s, CRE, URE)].append(s)
    print("\n=== 字符串分类 ===")
    for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print("  %-12s %7d" % (k, len(v)))

    # 导出各类
    for k, v in buckets.items():
        with open(os.path.join(out_dir, "str_%s.txt" % k), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(v)))

    # ---- 合并所有能识别的类描述符（str_class + 之前雕刻结果里也能补）----
    classes = set(buckets.get("class", []))
    # string_data 里类描述符常常不带 L; 前缀判断，补一遍
    for s in strings:
        if s.startswith("Lcom/") or s.startswith("Landroidx/") or \
           s.startswith("Lorg/") or s.startswith("Lkotlin"):
            if s.endswith(";") and " " not in s:
                classes.add(s)

    print("\n=== 类描述符合计 %d 个 ===" % len(classes))

    # ---- 模块分类 ----
    mod_counter = collections.Counter()
    mod_classes = collections.defaultdict(list)
    sub_counter = collections.Counter()
    for c in classes:
        mod, second = classify_module(c)
        mod_counter[mod] += 1
        mod_classes[mod].append(c)
        sub_counter[second] += 1

    print("\n=== 功能模块分布 ===")
    for m, n in mod_counter.most_common():
        print("  %6d  %s" % (n, m))

    # 源码地图（每个类 -> 模块）
    with open(os.path.join(out_dir, "source_map.tsv"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("class\tmodule\tpackage\n")
        for c in sorted(classes):
            m, second = classify_module(c)
            f.write("%s\t%s\t%s\n" % (c, m, second))

    # 每个模块单独一份类清单，方便逐块研究
    mod_dir = os.path.join(out_dir, "by_module")
    os.makedirs(mod_dir, exist_ok=True)
    for m, lst in mod_classes.items():
        safe = re.sub(r"[^\w\u4e00-\u9fff]+", "_", m)[:40]
        with open(os.path.join(mod_dir, safe + ".txt"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(lst)))

    # ---- 结构化摘要 ----
    summary = {
        "file_size": size,
        "string_pool_regions": len(regions),
        "unique_strings": len(strings),
        "string_buckets": {k: len(v) for k, v in buckets.items()},
        "unique_classes": len(classes),
        "modules": dict(mod_counter.most_common()),
        "top_packages": dict(sub_counter.most_common(60)),
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # ---- 中文业务文案（学习功能最有用的东西）----
    zh = sorted(buckets.get("text_zh", []))
    with open(os.path.join(out_dir, "chinese_text.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(zh))
    print("\n=== 中文业务文案 %d 条 ===" % len(zh))
    for s in zh[:15]:
        print("   ", s[:60])

    print("\n完成。产物在 %s" % os.path.abspath(out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
