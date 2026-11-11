# 案例：享做笔记 v7.6.1（爱加密 1011 版）

这篇是 `apk_analyze.py` 的实战记录，包含每一步的原始数据，可以对照着复现。

> 分析方式：纯静态，未运行 APK，未连接其服务器。
> 分析的包里没有任何用户数据，全部是公开发布的安装包。

---

## 一、基本信息

| 项目 | 值 |
|---|---|
| 应用名 | 享做笔记（英文 Xiangzuo / TouchNotes） |
| 包名 | `com.newskyer.draw` |
| versionName | Manifest 写 `7.0.3`，壳内常量是 `7.6.1_848` |
| versionCode | `142510`（壳内另有 `16`，是被改过的壳版本号） |
| compileSdk | 36 |
| 文件大小 | 475.7 MB / 7,061 个条目 |
| CPU 架构 | 仅 `arm64-v8a`（59 个 so，已放弃 32 位） |
| 厂商 | 广州新空电子科技有限公司（resources.arsc 内可见 Copyright） |
| 加固 | **爱加密 iJiami 1011 版** |

## 二、加固识别

```
lib/arm64-v8a/libijiami_1011.so          147 KB
assets/ijiami_1011.VData                 115 KB   magic = "ivmp\n02\0"
lib/arm64-v8a/libctmtp.so                953 KB   真正干活的 native 壳
lib/arm64-v8a/libctmtp-x86.so            1.1 MB
```

`assets/ijiami_1011.VData` 头部：

```
0000  69 76 6d 70 0a 30 32 00   ivmp.02.
...
00b0  <从这里开始就是高熵数据了>
```

`libctmtp.so` 的 ELF 结构被改过——section 名字是伪造的：

```
[1] .gnu.fragment   PROGBITS  0x190     0xc3e70    ← 其实是 .text
[5] .eh_intent      PROGBITS  0xd8000   0x8
[8] .gnu.draft      PROGBITS  0xd8040   0x11698
[9] .gnu.stub       PROGBITS  0xedb18   0x2200
```

导出表也是坏的（`local symbol 1 found at index >= .dynsym's sh_info value of 1`），
说明壳自己对 ELF 做了加工，常规工具链读不全。

## 三、DEX：只有 92 KB 是真的

```
文件           classes.dex (101.9 MB)
magic          'dex\n035'
header 声明     file_size=106857084（和实际长度一致，伪装过）
string_ids     1751 条 @0x70
type_ids       133 条
method_ids     1007 条
class_defs     30 个 @0x60ac
data 区间      0x646c ~ 0x167f4  (66,440 字节)

结论：真实数据只到 0x167f4，之后还有 101.8 MB 是密文
```

验证：整个文件里 `dex\n035` 只出现 1 次；`0x12345678`（DEX endian tag）出现 8 次，
除了开头那处，其余 7 处都是随机撞上的。

30 个真实类全是壳的加载器：

```
La/auu/a;                                    ← 字符串解密器
Lcom/ctZtamt/cym/ilajjtl/Entry;               ← 抽象入口
Lcom/ctZtamt/cym/ilajjtl/MyApplication;
Lcom/ctZtamt/cym/ilajjtl/MyJni;               ← native 桥
Lcom/ctZtamt/cym/ilajjtl/NEDialog;            ← 反调试弹窗
Lcom/ctZtamt/cym/ilajjtl/Utils;
Lcom/ctZtamt/cym/ilajjtl/a .. p;
Lcom/ctZtamt/cym/ilajjtl/plugin/InstrumentationProxy;
Lcom/ctZtamt/cym/ilajjtl/plugin/a .. g;
```

## 四、壳的工作流程（从壳类反编译结果还原）

```
1. g (AppComponentFactory) 在 instantiateClassLoader 阶段劫持 ClassLoader
2. f.a() 把 assets 里的 libctmtp.so 解到 /templib/，System.loadLibrary 加载
3. MyJni.cl() 是 native → 进入 libctmtp.so
   在那里解密 dex、用 BaseDexClassLoader / InMemoryDexClassLoader 动态加载
4. InstrumentationProxy 替换 ActivityThread.mInstrumentation
5. MyApplication.strAppName 指向真实 Application
6. 启动前跑 NEDialog 的反调试检查，命中就弹窗退出
```

关键字符串（全部由本工具还原）：

```
com.ctZtamt.cym.ilajjtl.MyApplication
com.ctZtamt.cym.ilajjtl.user.ReLinker
dalvik.system.BaseDexClassLoader
android.app.ActivityThread
currentActivityThread
mBoundApplication  /  mLoadedApk  /  mInstrumentation  /  mActivityThread
pathList  /  nativeLibraryDirectories  /  nativeLibraryPathElements
/templib/libctmtp.so  /  /templib/libs.zip  /  assets/.nesec_patch
/proc/self/maps  /  /system/bin/app_process
libctmtp  /  libctmtp64  /  libdexfix.so  /  libneguard.so
```

## 五、反调试检测项（19 条，全部还原）

壳启动时逐项检查，命中就弹窗并退出：

| 中文 | 英文 |
|---|---|
| 检测到调试器 | Detected the presence of a debugger. |
| 检测到Xposed环境 | Detected that the app is running in an Xposed environment. |
| 检测到在hook环境中运行 | ...running in a hooking environment. |
| 检测到root环境 | ...running in a rooted environment. |
| 检测到在模拟器中运行 | ...running on an emulator. |
| 检测到模拟点击环境 | ...in an environment with simulated clicks. |
| 检测到该应用已被篡改 | ...the application has been tampered. |
| 检测到该应用被注入so | ...the app has been injected. |
| 检测到在双开app中运行 | ...in a dual app environment. |
| 检测到USB调试开关打开 | ...the USB debugging mode is enabled. |
| 检测到VPN开启 | ...a VPN is being used. |
| 检测到代理环境 | ...a proxy is being used. |
| 检测到Rom异常 | Detected an abnormal ROM. |

还有一条很有意思的：

```
当前版本为加固试用版，请勿直接发布上线
```

说明这个壳本身带着试用期逻辑，正式包也可能包含这段代码。

## 六、字符串解密

算法：**Base64 解码 → 与 `b"Netease"` 循环异或**。

密钥是推导出来的，不是猜的：拿已知明文（Manifest 里明写的 `MyApplication` 类名）
和密文等长异或，得到的 37 字节正好是 `Netease` 循环 5 次多 2 位。

```python
import base64
KEY = b"Netease"

def dec(s):
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    raw = base64.b64decode(s)
    return bytes(b ^ KEY[i % 7] for i, b in enumerate(raw)).decode("utf-8", "replace")

dec("ORcVFREWFw==")                       # → 'wrapper'
dec("eUtCS1AsXXpd")                       # → '7.6.1_848'
dec("Kx0AFwAQEREWAwwVEA0RVQ==")           # → 'extract_switch_'
dec("LQoZSw8WEj0ODQATXQE8BAM=")           # → 'com.newskyer.draw'
```

遍历 1,751 条字符串池条目，**198 条命中**。注意必须过滤签名短码（`VDDDDDDDDD` 这类），
否则会得到 588 条噪音。

## 七、雕刻结果

```
类描述符      97,149 个
URL           568 个
可打印字符串  534,168 条
```

顶层包分布（按类数）：

```
 9,765  com/newskyer          ← 自家代码
 9,406  androidx/compose      ← Jetpack Compose
 8,903  com/google
 7,941  com/byazt             ← 穿山甲广告
 6,039  com/kwad              ← 快手广告
 4,826  com/dropbox
 4,395  com/huawei            ← HMS
 3,838  com/opos              ← OPPO 广告
 3,034  androidx/media3
 2,378  com/hihonor           ← 荣耀
 2,352  com/yfanads
 2,206  org/spongycastle
 1,736  androidx/camera
 1,661  io/reactivex
 1,551  org/bouncycastle
 1,523  io/ktor
 1,347  androidx/core
 1,334  com/amazonaws
 1,314  com/cicoe              ← 账号系统
 1,259  com/jd                 ← 京东广告
```

自家 9,765 个类分布在 61 个一级子包：

```
action activity ad adapter aidl analytics asr baidusync brush capture catalog
cloud colorpicker compose crop cropper databinding dialog doc_scan drag
dynamicmenu email file flashCards floatBall float_windows folderDevice gson
guide hvtoolbar layer live merge mindmapextension net note_navigation notetree
openad padActivityFeatures pay penboxtools record richText sensors service skin
splash sticker tab template toolmenu tools transfers user utils videoextension
views webexcerpt webfile widget
```

## 八、服务器地址

```
https://user.cicoe.net:29091/xzbj/app/v1        账号服务（非标准端口）
https://user.cicoe.net:30000/h5/page?key=yfwqy  H5 协议页
https://note.cicoe.net/                         笔记服务
https://paint.cicoe.net/qr/shop_infos           商城
https://paint.cicoe.net/qr/xiang_asr.apk        语音包 APK
https://doc.cicoenote.com/  https://manuals.cicoenote.com/
http://noteforeign.cicoe.net/note/en_privacy.html
http://manual.xiangzuobiji.com:8000/            帮助手册
http://web.draw.cicoe.net:29093/                Web 端
http://qa.mindmap.cicoe.com:12580/              ← QA 测试环境被打进了正式包
```

Deep Link：`cicoe.intent.action.OPEN_NOTE` → `note.cicoe.net/app`（App Links，autoVerify）

## 九、手写内核

`libdraw_811.so`（26 KB）导出了 46 个 JNI 函数，全部挂在 `com.newskyer.paint.PaintView` 下：

```
addPage / deletePage / restorePage / savePage / saveAllPagesAsPng / saveAsPng
cleanBoard / erase / undo / redo / touch / handle / handleOffset
getPixels / getPagePixels / savePixels / restorePixels / saveStatus / restoreStatus
setPenColor / setPenWidth / setBoardBackgroundColor / writeBackground / writeBg / writeRect
scale / setScreen / setSurface / updateSurface / showPoint / recordBoard
sign / signInfo / signX / isSigned / getCustomerName / getInfo
getQiniuAccessKey / getQiniuSecretKey / getRsaPublice / freePage
```

两个值得注意的点：

1. **`getQiniuAccessKey` / `getQiniuSecretKey`**——七牛的 AK/SK 从 native 层返回。
   客户端不应该持有账号级 SK，这是设计问题（虽然值在 native 里，静态拿不到）。

2. 文件里还硬编码了一段 RSA 公钥和一段固定串，并读取设备指纹：

```
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCx+PUrdAh5d2pBo1rlTz2YFaBi...
ajlO2WzgxyW0tdJxofjIr-CvJM8bWaGSyAoEaYmt

persist.sys.dmac
persist.sys.cpc
persist.sys.cinfo
/sys/class/net/eth0/address
/sys/class/net/wlan0/address
ro.board.platform
```

还有一段来自 Android 2.x 时代的 framebuffer 直接读写代码（`/dev/graphics/fb0`），
在新系统上无效，但说明这个内核代码历史很久。

## 十、内置模型（475 MB 的去向）

| 大小 | 内容 |
|---|---|
| 146 MB | `sherpa-onnx-sense-voice-cicoe-new/model.onnx.xz9e` 语音识别 |
| 38.7 MB | `ocr_v2_for_cpu/rec_crnn.nb` Paddle OCR 识别 |
| 26.3 MB | `ohr/v12_10k_fused_fp16.bin` 手写识别 |
| 23.6 MB | `tutorial/android_user_guide.pdf` 官方手册 |
| 22 + 19.5 + 7.6 MB | `formula_cpu/` 公式识别三件套 |
| 21.9 + 5 MB | `docapi/dochandwritingremoval` 手写擦除 |
| 16.4 MB | `libopencv_java4.so` |
| 15.3 MB | `libonnxruntime.so` |
| 12.3 + 9.4 MB | PDF OCR 检测模型 |
| 7.4 MB | `jieba/dict_processed.txt` 中文分词 |
| ~16 MB | `stickers/*.zip` 24 套贴纸 |

同一个 App 里同时用了 **Paddle-Lite(.nb) / ncnn / ONNX Runtime / 华为 HiAI** 四种推理框架，
是很好的"多框架选型"参考样本。

## 十一、明文凭据

分析中确认的（都是客户端内置、可被反编译拿到的）：

| 类型 | 值 |
|---|---|
| 神策埋点 | `https://xinkongdianzi.datasink.sensorsdata.cn/sa?project=production&token=ac559a1dba5200ee` |
| 华为 App ID | `101642035` |
| Bugly AppID | `4612bd9eba` |
| Dropbox App Key | `db-hs1era7x5zq049f` |
| 微信回调 | `sa50455c89` / `tnnews` / `sdksample` |

其中**神策 token 是实际可被滥用的**——拿到就能往对方埋点库里灌脏数据。

## 十二、这次分析没做到的

1. **方法体拿不到**。101.8 MB 密文没有解密，类结构和字符串是残留明文，不是真代码。
2. **native 壳没逆**。`libctmtp.so` 的 section 表被伪造、导出表被破坏，
   静态工具链读不全，需要动态调试才能看清解密流程。
3. **资源 ID 映射失效**。`resources.arsc` 被改过，jadx 报
   `value size, expected: 0x8, actual: 0x3`，所以拿不到 `@string/xxx` 这类资源名。
   字符串池本身能读，只是映射不到名字。
4. **七牛 AK/SK 的具体值**。在 native 里返回，静态拿不到。

---

## 复现

```bash
pip install -r requirements.txt   # 其实没有依赖，空文件
python apk_analyze.py base.apk out
cat out/report.txt
```

需要原包的话，从各大应用商店下载「享做笔记」即可，版本对得上就能复现上面的数字。
