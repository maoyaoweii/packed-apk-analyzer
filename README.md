# packed-apk-analyzer

> 一个零依赖的加固 APK 静态分析器。**不脱壳**，也能把一个装了壳的 APK 挖到能看懂的程度。

写它是为了回答一个问题：拿到一个 475 MB、被爱加密加固的 APK，jadx 只能反编译出 30 个类，还有没有办法搞清楚里面到底有什么？

答案是有的——而且不需要真机、不需要 Frida、不需要跑起来。

---

## 它做什么

| 步骤 | 做什么 | 产出 |
|---|---|---|
| 1 | ZIP 结构盘点、加固厂商识别 | 用了哪家壳、证据是什么 |
| 2 | 二进制 `AndroidManifest.xml` 解析 | 包名、版本、54 条权限、212 个 Activity |
| 3 | `resources.arsc` 字符串池解析 | 46,513 条界面文案（6,481 条中文） |
| 4 | DEX 结构分析 | 判定"这是壳 DEX"，算出真实数据只占多少 |
| 5 | 明文雕刻 | 从加密流里捞出 97,149 个类描述符、568 个 URL |
| 6 | 壳的字符串混淆还原 | 爱加密的 198 条密文全部还原成明文 |

---

## 核心思路

### 一、怎么判断一个 DEX 是壳

不是看类名、不是看有没有 `StubApp`，而是**看 header 声明的数据区能不能铺满整个文件**：

```python
data_end   = data_off + data_size
looks_packed = data_end < len(data) * 0.95
```

正常 DEX 里 `data_off + data_size` 约等于文件长度。
装壳之后，前面一小段是真数据，后面挂着一大坨加密内容，两者能差 100 MB：

```
data 区间   0x646c ~ 0x167f4 (66,440 字节)
真实数据只到 0x167f4，之后还有 101.8 MB 是密文
```

熵曲线也能直接看出来——加密段熵值明显偏高，文本段明显偏低。

### 二、不脱壳怎么拿到类结构

加固工具通常**只加密代码段**（方法体），而 DEX 里的这些东西常常以明文残留：

- 类描述符 `Lcom/xxx/Yyy;`
- 字符串常量（URL、Toast 文案、字段名）
- 方法签名短码

所以直接对整块 101 MB 二进制做正则扫描，就能把类结构捞出来。
这一招在爱加密、乐固、梆梆上都能用，**成本几乎为零，信息量能到脱壳的 70%**。

```python
RE_CLASS = re.compile(rb"L(?:com|org|net|androidx|kotlin|io|cn)/[A-Za-z0-9_$/\-]{2,150};")
classes = {m.group() for m in RE_CLASS.finditer(dex_bytes)}
```

### 三、壳的字符串混淆怎么破

壳一般把关键字符串（类名、路径、反调试提示）混淆成 `a.auu.a.c("base64...")`。
破解分两步：

**第一步：把壳类的反编译结果读出来**，找到解密函数（本项目里是 `a.auu.a.c`）：

```java
byte[] raw = new a.auu.a().decode(str, 0);
byte[] key = {78, 101, 116, 101, 97, 115, 101};   // "Netease"
for (int i = 0; i < len; i++) raw[i] ^= key[i % 7];
return new String(raw, "utf-8");
```

**第二步：验证密钥**。拿一条已知明文（壳的 Application 类名在 Manifest 里是明文）与密文等长异或：

```
密文  LQoZSwIHPzoEGRFPEBwjSx0JABkPOglaKBgyFT4JHQYABwwhCw==
明文  com.ctZtamt.cym.ilajjtl.MyApplication
异或  NeteaseNeteaseNeteaseNeteaseNeteaseNe    ← 37 字节，正好是 "Netease" 循环
```

密钥确认后，遍历 DEX 的 **string_ids 表**（不是在整个文件里搜 `a.auu.a.c(`，因为调用指令本身被加密了），
把每条字符串当密文试解一次即可。

**关键细节**：字符串池里混着 `VDDDDDDDDD`（方法签名短码）、`CCCC` 这类合法常量，
拿它们当密文解出来必然是乱码，必须过滤：

```python
def looks_like_real_string(s):
    if "\ufffd" in s: return False                          # 必须是合法 UTF-8
    if not any(c.isalnum() or "\u4e00" <= c <= "\u9fff" for c in s):
        return False                                        # 不能全是符号
    return sum(c.isprintable() for c in s) / len(s) > 0.95  # 可打印占比
```

不过滤会得到 588 条噪音，过滤后是 198 条真货。

---

## 用法

```bash
python apk_analyze.py app.apk                  # 输出到 ./out
python apk_analyze.py app.apk result_dir       # 指定输出目录
python apk_analyze.py app.apk out --json       # 额外输出 report.json
```

只要 Python 3.8+，**不需要装任何第三方包**，不需要 Java，不需要 jadx。

### 输出文件

```
out/
├── report.txt              完整分析报告
├── report.json             结构化数据（脚本里好处理）
├── manifest_strings.txt    Manifest 字符串池
├── manifest 组件列表        在 report.txt 里
├── arsc_strings.txt        全部界面文案（46,513 条）
├── arsc_chinese.txt        只留中文（6,481 条）
├── classes_real.txt        DEX 里真实声明的类
├── classes_carved.txt      从加密流雕刻出的类描述符（97,149 个）
├── urls.txt                所有 URL（568 个）
├── strings_carved.txt      可打印字符串
└── ijiami_decoded.txt      壳的字符串还原结果
```

---

## 实战效果

拿「享做笔记 7.6.1」的正式包（475 MB，爱加密 1011 版）跑：

```
文件大小       475.7 MB / 7061 个条目
DEX            101.9 MB（真实代码只有 92 KB，其余是密文）
so 架构        arm64-v8a(59)

★ 爱加密 iJiami
  证据：lib/arm64-v8a/libijiami_1011.so
  证据：assets/ijiami_1011.VData

package        com.newskyer.draw
versionName    7.0.3（但壳里常量是 7.6.1_848）
权限           54 条，其中 9 条高危
Activity       212 个

DEX 结论       【加固壳 DEX】
真实类          30 个（全是壳的加载器）
雕刻类描述符    97,149 个
URL            568 个
壳字符串还原    198 条
```

完整案例见 [`docs/case-newskyer.md`](docs/case-newskyer.md)。

---

## 已知局限

这套方法是**静态**的，有几件事做不到，说清楚免得误判：

1. **拿不到方法体**。加密的代码段不解密就是拿不到，类结构和字符串是"残留明文"，不是真代码。
2. **native 里的东西看不到**。加壳核心逻辑在 `libctmtp.so`，密钥、真正的解密流程都在里面。
3. **`resources.arsc` 的资源 ID 映射可能失效**。爱加密会改资源表结构，jadx 会报
   `value size, expected: 0x8, actual: 0x3`。字符串池本身能读，但资源名映射拿不到。
4. **不同壳的字符串混淆算法不一样**。本项目只内置了爱加密的（Base64 + `Netease` 异或）。
   别的壳需要自己逆一遍解密函数，套路是一样的：找到解密方法 → 用已知明文推密钥 → 遍历字符串池。

### 想更进一步（要脱壳）

如果确实需要真代码，就得动态脱壳：真机/模拟器 + Frida，hook 这些点 dump 内存里的 DEX：

```
DexFile.<init>
InMemoryDexClassLoader.<init>
DexClassLoader.<init>
BaseDexClassLoader.<init>
```

这属于另一套工具链，不在本项目的范围内。

---

## 两个工具

| 脚本 | 用途 |
|---|---|
| [`apk_analyze.py`](apk_analyze.py) | 主程序：Manifest / arsc / DEX 结构 / 加固识别 / 壳字符串还原 |
| [`deep_carve.py`](deep_carve.py) | 深挖：按顺序解析 DEX `string_data`，系统性还原字符串池并给全部类做功能分类 |

详见 [`docs/deep-carve.md`](docs/deep-carve.md)。

## 文件说明

```
apk_analyze.py    主程序（单文件，约 770 行）
deep_carve.py     字符串池还原 + 源码地图（约 300 行）
tests/            38 项自测
docs/             案例、深挖笔记、源码地图摘要
```

## 许可

MIT
