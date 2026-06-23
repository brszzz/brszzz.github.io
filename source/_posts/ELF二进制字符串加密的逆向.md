---
title: ELF 二进制字符串加密的逆向
date: 2026-06-23 19:59:00
tags:
  - ELF
  - ARM64
  - 字符串加密
  - 逆向工程
  - Android
  - 流密码
  - IDA-Pro
  - Python
  - 反混淆
  - 加壳
categories:
  - 逆向工程
description: 逆向一个 Android ARM64 ELF 的自定义字符串加密方案，还原双 pass 流密码算法（含 KEY_TERM 完整性锚点机制），写 Python 脚本一次性解密全部 956 条字符串。顺带发现一个 NEON 加壳框架。
---

# ELF 二进制字符串加密的逆向

> 前一阵拿到一个 Android ARM64 的静态 ELF，里面所有字符串都是加密的，strings 一把下去啥也看不见。花了两天把它的保护方案完整逆了出来，写篇记录分享一下过程。

---

## 0. 先说说这东西长什么样

文件是个独立可执行的 ELF，3357 个函数，1438 个字符串——说是 1438，实际上 IDA 识别出来的全是密文，没有一条能直接读。

大致结构：

| 段 | 作用 |
|---|---|
| `.text` | 3357 个函数，`.init_array` 里挂了一个 ctor |
| `.rodata` | 956 条加密字符串的密文池 |
| `.data.rel.ro` | 956 个 40 字节的描述符结构，每个指向密文 + 存密钥 |
| `.data` `0x1B7FB0..C7` | 24 字节的"完整性锚点"，后面会详细说 |
| `.packinfo` `0x1B8180` | 自定义壳的元数据段 |

关键函数一览：

| 地址 | 角色 |
|---|---|
| `sub_127A10` | `.init_array` ctor，壳解密器（这个版本没启用） |
| `sub_F5AC8` | 主业务入口，75 KB，大到 Hex-Rays 拒绝反编译 |
| `sub_10F13C / 10F2F4 / 10F408` | **字符串解密的三层调用链**——今天的重点 |
| `sub_6A7C0` | 唯一的 `system()` 入口，所有 shell 命令都走这里 |

---

## 1. 从"找不到字符串"说起

拿到样本先跑 `strings`，基本全是乱码。用 IDA 打开，所有交叉引用指向的字符串也读不了。这说明 **字符串不是简单的异或，而且每个引用点有自己的解密参数**。

在 `.data.rel.ro` 段里发现了规律：每隔 40 字节出现一个结构体，里面有两个指针、两个长度、还有一个 16 位的短整数。结构大致是这样：

```c
struct str_entry {      // 40 字节
    const u8* ptr1;     // offset 0   — 指向 .rodata 密文段1
    size_t    len1;     // offset 8
    const u8* ptr2;     // offset 16  — 指向 .rodata 密文段2（可为0）
    size_t    len2;     // offset 24
    u16       key;      // offset 32  — 16 位密钥
    u8        _pad[6];  // offset 34..39
};
```

也就是说，**每条加密字符串都对应一个 40 字节的描述符**，里面存了密文在哪、多长、以及解密密钥。956 条字符串就有 956 个这样的描述符。

这就好办了——找到了密文和密钥的存放位置，接下来只需要搞清楚解密算法。

---

## 2. 追解密函数

### 2.1 三层调用链

随便找一个引用加密字符串的地方，比如某处 `BL sub_10F13C`，跟进去。调用关系是这样的：

```
sub_10F13C(out_pair, &entry)               ← 调用者一次解一条
   │
   ├─ sub_10F2F4(&out1, ptr1, len1, key)
   │     └─ sub_10F408(buf, len1, key)     ← 核心解密器
   │
   └─ if (ptr2) sub_10F2F4(&out2, ptr2, len2, key ^ 0xBEEF)
         └─ sub_10F408(buf, len2, key ^ 0xBEEF)

最后 sub_10F13C 把 out1 || out2 拼接成完整字符串返回
```

注意几个关键信息：

- **双段结构**：一条字符串可能分两段存放，第二段的密钥要异或 `0xBEEF`
- **核心算法在 `sub_10F408`**：输入是密文 buffer + 长度 + 16 位密钥
- 第一段和第二段用的是**同一个核心算法**，只是密钥不同

### 2.2 找到"完整性锚点" KEY_TERM

在追 `sub_10F408` 之前，先要解决一个前置问题。在 `.data` 段 `0x1B7FB0` 处有一块 24 字节的硬编码数据：

```
91 e9 3e b8 29 b1 8b 92  03 e1 4e 1a 52 c3 a7 88
fb 9e 17 66 23 6d ec 31
```

在 `sub_10F408` 的代码里，这 24 字节被一个固定的算法折叠成一个 32 位常量 `KEY_TERM`：

```c
// 偶数下标 vs 奇数下标的字节做 XOR，覆盖全部 24 字节
A  =  B[8] ^ B[0]  ^ B[16] ^ B[4]  ^ B[12] ^ B[20]
Bc = (B[2] ^ B[10] ^ B[18] ^ B[6]  ^ B[14] ^ B[22]) ^ 0xB8
KEY_TERM = A | (Bc << 16)        // 实测 = 0x1F0031
```

这个 `KEY_TERM` 会参与 `sub_10F408` 里每一轮的状态计算。换句话说，**这 24 字节是嵌死在二进制里的"第二把钥匙"**——你即使拿到了 40 字节描述符里的 key，没有正确的 `KEY_TERM` 也解不出来。动其中任意一个字节，所有 956 条字符串全部乱码。

这算是一种**绑定二进制的反剥离**：把 ELF 的 `.data` 段单独 dump 出来没用，patch 任何一个字节也会破坏解密。

### 2.3 核心算法 `sub_10F408`：双 pass 流密码

这是最核心的部分。`sub_10F408` 地址在 `0x10F408`，做两遍变换，每一遍都像一个自制的流密码。

先看它用到的魔术常量：

| 常量 | 数值 | 来源/说明 |
|---|---|---|
| `DELTA` | `0x7A35D295` | 自定义"前进步长" |
| `NEG` | `0x9E3779B9` | 黄金分割比的 32 位整数化（TEA/XXTEA 同款） |
| — | `0xA5A5` | 密钥变换用 |
| — | `0xA2F9836E` | π 的 32 位整数化 |
| — | `0xF4764525` | 自定义常量 |
| — | `0x517CC1B7` | √2 的 32 位整数化 |
| — | `0xBEEF` | 段 2 密钥的异或掩码 |

一眼就能看出来作者在借用 TEA 系列的魔术常量，但算法结构完全是自创的，跟 TEA 没有直接关系。

#### Pass 1：双状态机正向 + 反向交替

翻译成伪代码大概是这样：

```c
v3 = DELTA - DELTA * n;     // 注意：长度 n 参与初始化！
v4 = 0;

for (i = 0; i < n; i++) {
    // 状态机 1：正向推进
    v7  = v3 ^ ROR(NEG * (key ^ 0xA5A5) ^ 0xA2F9836E ^ KEY_TERM, 21);
    v3 += DELTA;
    s7  = ROL32(v7, 5);
    t   = d[i] ^ (s7 & 0xFF) ^ ((s7 >> 16) & 0xFF);
    t   = ROL8(t, 4);        // 字节级 4 位旋转

    // 状态机 2：反向推进
    v10 = v4 ^ ROR(NEG * key ^ 0xF4764525 ^ KEY_TERM, 21);
    v4 -= DELTA;
    s10 = ROL32(v10, 5);
    d[i] = t ^ (s10 & 0xFF) ^ ((s10 >> 16) & 0xFF);
}
```

几个值得注意的点：

- **`v3` 用 `DELTA - DELTA * n` 初始化**，意味着长度参与状态——你如果截短哪怕一个字节，整条串都解不对
- **v3 正向加 DELTA，v4 反向减 DELTA**——"左右开弓"，相邻字节的掩码完全无关
- **`ROL8(t, 4)`** 字节级旋转是用来破坏纯线性关系的——如果去掉这步，整个加密就退化成简单的异或流

#### Pass 2：第二遍，引入减法

```c
v11 = 0;
v12 = NEG * key;

for (i = 0; i < n; i++) {
    v13 = v11 ^ ROR(v12 ^ 0x517CC1B7 ^ KEY_TERM, 21);
    s13 = ROL32(v13, 5);
    v14 = (d[i] - ((s13 & 0xFF) ^ ((s13 >> 16) & 0xFF))) & 0xFF;
    v14 = ROL8(v14, 5);      // 注意：这里是 rol8(5)，和 Pass 1 的 rol8(4) 不同！

    v15 = v11 ^ ROR(KEY_TERM ^ v12, 21);
    v11 -= DELTA;            // 状态反向推进
    s15 = ROL32(v15, 5);
    d[i] = v14 ^ (s15 & 0xFF) ^ ((s15 >> 16) & 0xFF);
}
```

Pass 2 跟 Pass 1 最大的不同是**把异或换成了减法**：`d[i] - mask` 而不是 `d[i] ^ mask`。减法不满足交换律，这让"密文 = 明文 XOR 流密钥"这种简单假设彻底失效。

两遍叠加下来：**字节维度上非线性、位置相关、长度相关、密钥相关**。

### 2.4 验证：这个变换是自反的

写脚本之前先要确认一件事：加密和解密是不是同一个函数？

用 IDAPython 在调试器里设断点实测了一条已知字符串——调用 `sub_10F408` 前是密文，调用后变明文。又试了把明文当输入再调一次——输出变回密文。

**确认：`sub_10F408` 是自反变换（involution），加密和解密是同一个操作。** 这就省事了，不需要分别实现 encrypt 和 decrypt。

---

## 3. 写 Python 解密脚本

### 3.1 复刻核心算法

理解了算法之后，翻译成 Python 就很直接了：

```python
DELTA, NEG = 0x7A35D295, 0x9E3779B9
KEY_TERM = 0x1F0031   # 从 byte_1B7FB0..C7 的 24 字节推导出来

def u32(x):       return x & 0xFFFFFFFF
def rol(x, r, w=32): m = (1 << w) - 1; r %= w; return ((x << r) | (x >> (w - r))) & m
def ror(x, r, w=32): m = (1 << w) - 1; r %= w; return ((x >> r) | (x << (w - r))) & m

def decrypt(ct: bytes, key: int) -> bytes:
    d = bytearray(ct)
    n = len(d)
    if n == 0:
        return bytes(d)

    # ===== Pass 1 =====
    v3 = u32(DELTA - DELTA * n)
    v4 = 0
    for i in range(n):
        s7  = rol(u32(v3 ^ ror(u32(NEG * (key ^ 0xA5A5)) ^ 0xA2F9836E ^ KEY_TERM, 21)), 5)
        v3  = u32(v3 + DELTA)
        t   = rol((d[i] ^ (s7 & 0xFF) ^ ((s7 >> 16) & 0xFF)) & 0xFF, 4, 8)

        s10 = rol(u32(v4 ^ ror(u32(NEG * key) ^ 0xF4764525 ^ KEY_TERM, 21)), 5)
        v4  = u32(v4 - DELTA)
        d[i] = t ^ (s10 & 0xFF) ^ ((s10 >> 16) & 0xFF)

    # ===== Pass 2 =====
    v11 = 0
    v12 = u32(NEG * key)
    for i in range(n):
        s13 = rol(u32(v11 ^ ror(v12 ^ 0x517CC1B7 ^ KEY_TERM, 21)), 5)
        v14 = rol((d[i] - ((s13 & 0xFF) ^ ((s13 >> 16) & 0xFF))) & 0xFF, 5, 8)

        s15 = rol(u32(v11 ^ ror(KEY_TERM ^ v12, 21)), 5)
        v11 = u32(v11 - DELTA)
        d[i] = v14 ^ (s15 & 0xFF) ^ ((s15 >> 16) & 0xFF)

    return bytes(d)
```

### 3.2 处理双段结构

有了核心解密函数，再包一层处理描述符的双段逻辑：

```python
def decrypt_entry(seg1: bytes, seg2: bytes, key: int) -> bytes:
    """完整解一条字符串：两段密文 + 16 位密钥"""
    out = b''
    if seg1:
        out += decrypt(seg1, key)
    if seg2:
        out += decrypt(seg2, key ^ 0xBEEF)
    return out
```

### 3.3 写 IDAPython 批量扫描脚本

描述符都在 `.data.rel.ro` 段里，结构固定 40 字节。写个 IDAPython 脚本遍历：

```python
import ida_bytes
import idc

# 假设已经确定了描述符的起始和结束地址范围
# 每个 40 字节的结构：
#   +0: ptr1 (8 bytes)
#   +8: len1 (8 bytes)
#  +16: ptr2 (8 bytes)
# +24: len2 (8 bytes)
# +32: key  (2 bytes)

def scan_and_decrypt(start_ea, end_ea):
    results = []
    ea = start_ea
    while ea < end_ea:
        ptr1 = ida_bytes.get_qword(ea + 0)
        len1 = ida_bytes.get_qword(ea + 8)
        ptr2 = ida_bytes.get_qword(ea + 16)
        len2 = ida_bytes.get_qword(ea + 24)
        key  = ida_bytes.get_word(ea + 32)

        seg1 = ida_bytes.get_bytes(ptr1, len1) if ptr1 and len1 else b''
        seg2 = ida_bytes.get_bytes(ptr2, len2) if ptr2 and len2 else b''

        try:
            plain = decrypt_entry(seg1, seg2, key)
            results.append((ea, plain.decode('utf-8', errors='replace')))
        except:
            results.append((ea, '<decrypt failed>'))

        ea += 40

    return results
```

实际跑一遍，956 条全部解密成功，耗时不到 5 秒。

---

## 4. 为什么这套保护"一击就碎"

回头看看这套方案的设计意图和实际效果。

作者想防的东西：

| 层 | 想防什么 |
|---|---|
| 双段 + key ^ 0xBEEF | 不让逆向者直接把 `.rodata` dump 出来就能读 |
| KEY_TERM 绑 24 字节常量 | 二进制剥离/patch 后解不出来 |
| DELTA * n 初始化 | 截短密文就全乱 |
| 双状态机 + Pass 2 减法 | 抵抗差分分析 |
| 各种魔术常量 | 看起来像 TEA，增加迷惑性 |

但实际上，它缺了几个关键的东西：

- **没有 PRNG / KDF**：全部状态只依赖于 `(key, n, KEY_TERM)` 三个值
- **没有外部熵**：不读 `/proc/*`、不读时间、不读设备标识
- **KEY_TERM 又是从二进制硬编码算出来的**：拿到二进制就拿到一切

所以结论很简单——**它是混淆（obfuscation），不是密码学**。只要把 `sub_10F408` 的算法逆出来，所有密文一次性全解。

我猜作者可能也知道这点。这套东西的真正目的不是防专业逆向，而是**提高静态分析的自动化门槛**——让 strings、grep 这类工具彻底失灵，让基于特征码的自动扫描也扫不出东西。

---

## 5. 顺带发现的壳框架

除了字符串加密，这个 ELF 还埋了一个自定义的加壳框架，虽然这个版本没启用。

`.packinfo` 段在 `0x1B8180`，结构很简单：

```c
struct packinfo_hdr {        // 16 字节
    uint32_t magic;          // 'PACK' = 0x5041434B
    uint32_t count;          // 3（这个版本硬编码必须等于 3）
    uint64_t _pad;
};

struct packinfo_entry {      // 0x18 字节
    uint64_t _reserved;
    uint64_t segment_rva;    // 待解密区段的相对地址
    uint64_t segment_len;    // 长度
};
```

解密器是 `sub_127A10`，挂在 `.init_array` 里，在 `main()` 之前由 loader 调用。用的是 NEON 指令做 XOR + ROL3：

```asm
EOR   V3.16B, V4.16B, V3.16B    ; D ^= K1
USHR  V5.16B, V3.16B, #5
SHL   V3.16B, V3.16B, #3
ORR   V3.16B, V3.16B, V5.16B    ; ROL by 3（字节级）
EOR   V3.16B, V3.16B, V4.16B    ; ^= K2
```

密钥 `K1`/`K2` 本身还经过三张 NEON TBL 表做了置换，不能直接从 `.data` dump 出来直接用。

里面还带了一个反 dump 的 fence——解密前要先调 `dladdr(&packinfo, &info)` 确认自己在原版 ELF 里跑。如果你把 ELF 复制到别的 loader 里分析，`dladdr` 找不到基址，整个壳就静默关闭。

不过在当前版本里，三个 entry 全是 0——也就是说没有任何区段被实际加密。这只是个**框架**，下一版填上区段地址就能用。

---

## 6. 解密结果能告诉我们什么（部分示例）

956 条字符串全部解出来后，程序的行为就一目了然了。这里只举几个典型的例子来说明解密的价值，完整列表就不贴了。

**Shell 命令模板类：**

所有的命令都走同一个入口 `sub_6A7C0`，这个函数做的事就是把三段解密出来的固定字符串拼成：

```
/system/bin/sh -c "<模板命令>" 1>/dev/null 2>&1
```

三段密文的解密参数：

| 入口地址 | seg1 偏移 | len1 | key | 解密结果 |
|---|---|---|---|---|
| `0x1A2C48` | `0x220CF` | 19 | `0x0000` | `/system/bin/sh -c "` |
| `0x1A4958` | `0x234F0` | 18 | `0x01E4` | `" 1>/dev/null 2>&1` |
| `0x1A9CC8` | `0x2703D` | 1 | `0x027A` | `"` |

中间那个 `<模板命令>` 就是从其他 956 条字符串里解出来的。整个二进制里 `sub_6A7C0` 被调用了 412 次，**每条命令模板都硬编码在二进制里，没有任何一条来自网络**。

**命令类型大致分布：**

- **文件删除类**：清各种 SDK 缓存和系统追踪文件，比如 `rm -rf <某应用数据目录>/cache/*`、清 `/data/system/dropbox`、清 `/data/anr` 等等
- **设备标识篡改类**：用 `resetprop` 和 `settings put` 伪造几十个系统属性和设置项——这是脚本的核心功能，大约占了 130+ 条命令
- **网络重置类**：`iptables`/`ip6tables` 清规则、`ifconfig wlan0 hw ether` 改 MAC、飞行模式开关等
- **包管理类**：`pm path`、`pm install -r`、`am force-stop` 等
- **内核参数调整类**：`echo` 往 `/proc/sys/` 写值，比如提高 inotify 上限、关 ptrace 限制等

**License 校验相关：**

解出来一个域名和几个 HTTP POST 参数模板，拼起来大概是这样：

```
POST /<path> HTTP/1.1
Host: <某个域名>
Content-Type: application/x-www-form-urlencoded

id=<SKU>&kami=<卡密>&sign=<签名>
```

就是个明文 HTTP 的卡密激活校验，不是远程控制通道。

---

## 7. 总结一下这个过程的收获

回头看整个逆向过程，核心就是三步：

1. **找到密文和密钥的存放位置**（`.data.rel.ro` 里的 40 字节描述符）
2. **逆向核心解密算法**（`sub_10F408` 的双 pass 流密码 + `KEY_TERM` 锚点）
3. **写脚本批量解密**（Python 复刻算法 + IDAPython 遍历描述符）

其中第 2 步花的时间最多。`sub_10F408` 的伪代码大概 40 行，但是双状态机 + 两遍不同变换叠在一起，静态看很容易绕晕。解决思路是：先不管那些魔术常量从哪来的，把循环结构和数据流图画清楚；再用 IDA 的调试器对一条已知字符串下单步跟踪，验证伪代码的每一步——看寄存器里的值跟自己的理解是否对得上。

有一个小技巧值得提：当你怀疑某个变换是不是自反的时候，**直接拿明文跑一遍，看输出是不是密文**。比推导逆变换快多了。

另外，`KEY_TERM` 这个"完整性锚点"的设计挺有意思。它本质上是把二进制本身变成了密钥材料——你如果拿不到原始 ELF（比如只有内存 dump），或者 patch 了 `.data` 段的任何一个字节，解密就会全盘失败。但这种"绑定"在拿到了完整二进制文件之后就不起作用了，因为 24 字节常量是死的。

这篇文章就到这儿。后面如果有时间，可能会再写写那个 NEON 壳框架的详细分析，以及 HTTP 解析器那块的一些发现。
