---
title: 某 UE4 手游字符串解密与 FNamePool 定位全过程
date: 2026-06-18 00:00:00
tags:
  - ARM64
  - IDA Pro
  - Unreal Engine 4
  - FName
  - 逆向分析
  - 游戏安全
  - LTO
  - NEON
categories:
  - 编程开发
description: "从一个被 Clang LTO 全 unroll 编译爆体积的 93KB UE4 函数出发，先把误判为 OLLVM 的 FName::LookupOrAdd 还原为正常逻辑，再逐 case 抓出 FName 字符串的 9 路异或解密算法（窄路径 + 宽路径），最后定位 g_FNamePool 全局变量并落到可用于内存读取的 C++ 代码。"
---

## 0x0 起因

本篇文章分析一个 `E:\xxx_global\libUE4.so`（某款 UE4 手游的客户端库），首先找GName，根据BytePorperty交叉引用，找到了 `0xDB35E14` 这个函数，发现这个跟常规的FNamepool算法不太一样，像是什么混淆。第一眼数据吓人：

| 项 | 值 |
|---|---|
| 函数大小 | 93 356 字节 |
| 基本块数 | 3 965 |
| 圈复杂度 | 2 034 |
| 调用者 | 128 |
| 内嵌字符串 | `"None"`、`"N0ne"`、`"Nome"`、`"SHVector"`、`"Color"`、`"Plane"` 等 |

这个体量在 UE4 库里足够引人警惕：典型 OLLVM 平坦化函数也就是几千块。而且函数体里到处是「12 字节绕路块」、`byte_xxx` 形态的字节比较、以及看起来像 opaque predicate 的两路分支……

但只要静下心来跟着汇编走，会发现**它一行混淆都没有**。这篇文章把整个还原过程分阶段写出来，覆盖三件事：

1. 把"看起来像混淆的东西"拆掉，确认它就是 `FName::LookupOrAdd` 一次性初始化 + 查找/插入路径的 LTO 全展开版本；
2. 顺手把 UE4 在这个 .so 里用的 **9-case FName 字符串异或加密**（窄/宽双路径）逐字节还原；
3. 把全局变量 `g_FNamePool` 钉死在哪个地址、怎么从 `NameId` 反查到 entry 字节，给出可直接用于跨进程读内存的 C++。

> 全程使用 IDA Pro + IDA MCP，**不依赖 Hex-Rays 反编译**——所有结论从 disasm + helper 函数身份匹配得到。

## 0x1 第一轮误判：OLLVM？

第一次速读，给自己挖了个坑。函数特征看起来全中混淆：

- **「巨大 dispatcher」**：`0xDB36688` 是个频繁被跳到的地方，像极了 CFF 的 dispatcher 头；
- **「成对绕路块」**：每个 case 后面都跟一段 12 字节短块再跳回，像 Bogus Control Flow；
- **「opaque predicate」**：一些路径前面要先 `LDRB Wn, [bss byte]; CBZ Wn, ...`，bss 字节默认为 0，看似永远走一边；
- **「字符串扰动」**：`"N0ne"`/`"Nome"` 在 `"None"` 旁边出现，像在做字符串混淆。

按这个看法可以洋洋洒洒写一段「OLLVM 平坦化 + Bogus + Opaque」的报告。但接下来逐项验证就被打脸：

### 1.1 `0xDB36688` 不是 dispatcher，是函数 epilogue

```asm
db36688  LDR    X8, [X24, #0x28]      ; 取栈金丝雀
db3668c  LDUR   X9, [X29, #var_10]    ; 取栈上保存的金丝雀
db36690  CMP    X8, X9
db36694  B.NE   __stack_chk_fail
...
db366b8  RET
```

这是 AArch64 标配的 stack canary check + 寄存器恢复 + `RET`。所有"跳到 dispatcher"的边都是函数自然结束的边——只是因为函数太大，IDA CFG 把所有 return 边都画到这一个块上了。

### 1.2 那些 bss 字节是 `__cxa_guard`

挑一个观察：

```asm
db366bc  ADRL   X0, byte_1BACA1C0
db366c4  BL     sub_ECD0C74        ; ?
db366c8  CBZ    W0, ...
...
db366f8  BL     sub_ECD0C80        ; ?
```

`sub_ECD0C74` 的 PLT 跳板很短，进去到 stub 里立刻能看出原型 = `int __cxa_guard_acquire(uint64_t* guard)`——典型 Itanium C++ ABI 静态局部变量初始化守门函数。`sub_ECD0C80` 对应 `__cxa_guard_release`。这对函数不是混淆而是**C++ static local 一次性初始化**：

```
if (acquire(&guard)) {
    // 真正的初始化代码
    release(&guard);
}
```

那个被认为是 opaque predicate 的 byte 是 guard 字节，初始为 0，第一次进入设为 1，所以**第一次执行走真正初始化分支，之后永远走快路径**——和 opaque predicate 形态一样，但语义完全不同。

### 1.3 「成对短块」是 LTO 的展开 + 异常重入 trampoline

每个 12 字节"绕路块"看清楚都是：

```asm
loc_xxx:
   BL    sub_1093DD48              ; 内部又调一层 __cxa_guard 拿 GMalloc*
   B     主流
```

是 GCC/Clang 异常路径接回主流的样板代码——LTO 把"取全局单例"这种很普通的事情也给 inline 进来了，于是产生大量这种重入跳板。

### 1.4 `"N0ne"` / `"Nome"` 是 `NAME_None` 哨兵

UE4 源码本来就这样写。FNamePool 里 0 号项是 `None`，比较时为了区分"未初始化"和"真的是 None"，引擎内有 `"N0ne"`（数字 0）这种内部 sentinel 字串。和混淆无关。

### 1.5 真正的本质：LTO + 全 unroll

函数体 `0xDB35EC4..0xDB360EC` 这一段非常工整：每隔 0x80 步距，做一组 `pthread_rwlock_init` + 一组 `STP XZR/STR XZR` 清零。整整 16 组。换句话说——

```cpp
for (int i = 0; i < 16; ++i) {
    pthread_rwlock_init(&buckets[i].lock, NULL);
    memset(&buckets[i].data, 0, 0x40);
}
```

被 Clang 全部 unroll 了。这就是所谓的"巨大函数"的真相。

汇编里另一段长得像加密的代码：

```asm
... BL  sysinfo_ut
... LSR ... LSR ... CSEL ...
... 一串只跟 totalram 相关的位操作 ...
```

实际是 `ceil_log2(totalRAM * mem_unit)` 算 hash 桶容量初值——把整个 `__lzcnt` 风格做 unsigned ceil-log2 的代码片段也展开了。

到这里第一阶段闭合：函数不是混淆，是 **`FName::LookupOrAdd` 首次初始化 + 查找/插入全路径**，被 LTO 完全展开。

## 0x2 第二轮：把 FNamePool 布局抠出来

误判修正后，下一步是把数据结构钉死。看那个 16 桶 unroll 块的第一组：

```asm
db35edc  ADRL   X23, unk_1BB53A80          ; FNamePool 基址
db35ee8  STR    X0, [X23, #0x38]           ; pool->stringPool = GMalloc->Malloc(0x80000)
db35ef4  ADD    X8, X23, #0x10,LSL#12      ; X8 = pool + 0x10000
db35efc  ADD    X0, X8, #0x80              ; X0 = pool + 0x10080  → bucket[0].lock
db35f08  BL     pthread_rwlock_init_ut     ; init(&bucket[0].lock, NULL)
```

接下来同款代码每组步进 `+0x80` 做 16 次。整个 FNamePool 长这样：

```c
struct FNameHashBucket {            // 0x80 字节
    pthread_rwlock_t lock;          // +0x00..0x38  (Bionic 是 0x38)
    uint32_t cursor;                // +0x38  arena 写入游标
    uint32_t mask;                  // +0x3C  hash 表大小 - 1
    void*    hashTable;             // +0x40  uint32_t[mask+1] 槽数组
    void*    entryArena;            // +0x48  arena slot 数组基址
    /* +0x4C..0x7F 各种 SoA 统计字段 */
};

struct FNamePool {
    uint8_t        pad_0[0x10038];
    void*          stringPool;      // +0x10038  GMalloc 给的 0x80000 字符串池
    uint32_t       stringPoolUsed;  // +0x10050
    uint32_t       stringPoolReserve;// +0x10054
    uint8_t        pad_1[0x2C];
    FNameHashBucket buckets[16];    // +0x10080，stride 0x80
};
```

值得强调的两点：

1. **`unk_1BB53A80` 不是指针变量，是结构体本体的 BSS 起点**。代码里直接 `ADRL X23, unk_1BB53A80` 拿地址，没有 `LDR X23, [X23]` 这种解引用动作。所以 `g_FNamePool = libUE4.so 模块基址 + 0x1BB53A80`，**不要再 deref**。
2. `0x1BB53AB8` 这个被 IDA 起名 `qword_1BB53AB8` 的"独立全局变量"不是独立的——它是 pool 的 `+0x38` 成员（`stringPool` 指针）。dump 内存可以看到它的值落在堆地址段（高位 `0x7c…`），证明是 GMalloc 返回的池基址。

把这些都改名标到 IDB 里：

```
0x1BB53A80  unk_1BB53A80     →  g_FNamePool
0x1BB53AB8  qword_1BB53AB8   →  g_FNamePool_StringPool
0xDB35E14   sub_DB35E14      →  FName_StaticInit_LookupOrAdd
0xDB4D45C   sub_DB4D45C      →  FName_CompareEntryChars
0xDB4CE9C   sub_DB4CE9C      →  FName_HashString
0xECD6574   sub_ECD6574      →  pthread_rwlock_init_ut
0xECD0C74   sub_ECD0C74      →  cxa_guard_acquire_ut
0xECD0C80   sub_ECD0C80      →  cxa_guard_release_ut
... (其余 helper 也按标准库符号补齐)
```

## 0x3 第三轮：FName 字符串加密的 9 路 case 算法逆向

这一节是整个逆向最磨人的部分——FName entry 在池里**不是明文存的**，而是用一个由 `len` 派生的 key 异或过的字节流，且窄/宽两条路径用了**两份不同**的 9-case 算法。下面分四步还原。

### 3.1 入口判别：怎么发现这是"9-case 派发"

切入点不是 `FName_StaticInit_LookupOrAdd` 自己（93KB 太大），而是它在 hash 命中后会调的一个小函数 `sub_DB4D45C`（2.5KB / 197 块），看起来像个比较器。disasm 它的 prologue：

```asm
db4d48c  LDRH   W23, [X8],#2          ; header = *(u16*)entry; entry+=2
db4d490  TBNZ   W23, #0, loc_DB4DCC0  ; if (header & 1) goto wide_path  ← is_wide
db4d494  LSR    X20, X23, #6          ; len = header >> 6
```

读到这里有 3 个先验信号：

1. `LDRH ... [X8],#2` 是「读两字节并步进」——典型 FNameEntry header 行为；
2. `TBNZ W23,#0` 测 bit0——经验上 UE4 的 `is_wide`；
3. `LSR X20, X23, #6` 左移 6 位提 len——也是 UE4 标准 header 编码。

紧接着出现一段不寻常的算式：

```asm
db4d4ac  MOV    W8, #0x1C72
db4d4b0  MUL    W8, W20, W8
db4d4b4  LSR    W8, W8, #0x10
db4d4b8  ADD    W8, W8, W8,LSL#3
db4d4bc  SUB    W8, W20, W8           ; case_id = len - (len/9)*9 = len % 9
db4d4c0  AND    W9, W8, #0xFFFF
db4d4c8  CMP    W9, #3
db4d4cc  B.LE   ...                   ; 9 路 switch 派发
```

`MOV #0x1C72 / MUL / LSR #16 / ADD,LSL#3 / SUB` 是经典 Hacker's Delight 风格的无除法取模 9：`floor((1<<16)/9) = 7282 = 0x1C72`，`(x*0x1C72)>>16` 是 `x/9` 的近似商，再乘 9（用 `q + q*8`）减回去得余数。**只要看到 `0x1C72` 这个魔术常数，就能确认是 `% 9`**——这是后面一切的派发轴。

后面的 `B.LE/B.NE/B.EQ` 形成一棵嵌套二叉派发树，9 个 case 散布在 `0xDB4D4EC..0xDB4DD48` 范围内。

### 3.2 用 IDA MCP 把 9 个 case 抓全

最笨的办法是把 2.5KB 函数从头读到尾，逐个识别 case。但函数体里 case 之间夹了大量 NEON 循环、标量回退、跨块跳转，肉眼很容易跟丢。我选择**用指令查询反向定位**：

每个 case 的"指纹"是一条 `AND W8, W8, #imm` 后面紧接 `DUP V0.16B, W8`——前者是 mask，后者把 key 字节广播成 16 字节给 NEON 用。先用 `insn_query` 列出函数内所有 `AND/EOR/MVN`：

```
mnem=AND, func=0xDB4D45C   →  32 条
mnem=EOR, func=0xDB4D45C   →  24 条
mnem=MVN, func=0xDB4D45C   →  21 条
```

`AND` 32 条里大部分是循环对齐用的 `& 0x3F0` / `& 0x3F8`，剔除后剩下 9 条不同立即数：

```
db4d504  AND  W8, W8, #0x1F80     ← case 6
db4d598  AND  W8, W8, #0x780      ← case 2
db4d620  AND  W8, W8, #0x780      ← case 4
db4d6a8  AND  W8, W8, #0x780      ← case 1
db4d730  AND  W8, W8, #0x1F80     ← case 5
db4d814  AND  W8, W8, #0x780      ← case 7
db4d89c  AND  W8, W8, #0xFF80     ← case 3
db4d924  AND  W8, W8, #0x780      ← case 8 (后来纠正)
db4dd60  AND  W8, W8, #0x780      ← case 0
```

——清单一目了然。

接着倒回去看每条 mask 上面 5–10 行，把"算 key 的子表达式"反推出来。比如 case 6 块 `0xDB4D4EC..0xDB4D504`：

```asm
db4d4ec  MOV    W8, #5
db4d4f0  CMP    W20, #1
db4d4f4  ORR    W8, W8, W20,LSL#2     ; W8 = 5 | (len<<2)
db4d500  ADD    W8, W8, W20            ; W8 += len
db4d504  AND    W8, W8, #0x1F80        ; key = ... & 0x1F80
db4d514  DUP    V0.16B, W8             ; broadcast 低 8 位
db4d52c  EOR    V1.16B, V0.16B, V1.16B
db4d530  MVN    V1.16B, V1.16B         ; out = ~(src ^ key)
```

→ `key = ((5 | (len<<2)) + len) & 0x1F80`。

9 个 case 同样套路抓一遍：

| case (`len % 9`) | 块 | 关键指令 | 真实 key 表达式 |
|---|---|---|---|
| 0 | `0xDB4DD48` | `EOR W8, W20, #0x40 ; ADD W8, W20 ; AND #0x780` | `((len ^ 0x40) + len) & 0x780` |
| 1 | `0xDB4D690` | `MOV W8,#0xDF ; EOR W8, W23,LSR#6 ; ADD W8, W20 ; AND #0x780` | `(((header>>6) ^ 0xDF) + len) & 0x780` |
| 2 | `0xDB4D580` | `MOV W8,#0xCF ; ORR W8, W20, W8 ; ADD W8, W20 ; AND #0x780` | `((len \| 0xCF) + len) & 0x780` |
| 3 | `0xDB4D888` | `UBFX X8,X23,#6,#0x1A ; ADD W8,W8,W8,LSL#5 ; AND #0xFF80` | `((header>>6) * 0x21) & 0xFF80` |
| 4 | `0xDB4D60C` | `UBFX X8,X23,#8,#0x18 ; ADD W8,W8,W23,LSR#6 ; AND #0x780` | `((header>>8) + (header>>6)) & 0x780` |
| 5 | `0xDB4D71C` | `ADD W8,W20,W20,LSL#1 ; ADD W8,#5 ; AND #0x1F80` | `(3*len + 5) & 0x1F80` |
| 6 | `0xDB4D4EC` | `MOV W8,#5 ; ORR W8,W8,W20,LSL#2 ; ADD W8,W20 ; AND #0x1F80` | `((5 \| (len<<2)) + len) & 0x1F80` |
| 7 | `0xDB4D7FC` | `LSR W8,W23,#0xA ; ORR #7 ; ADD W8,W23,LSR#6 ; AND #0x780` | `(((header>>10) \| 7) + (header>>6)) & 0x780` |
| 8 | `0xDB4D910` | `EOR W8,W20,#0xC ; ADD W8,W20 ; AND #0x780` | `((len ^ 0x0C) + len) & 0x780` |

**踩坑记录**：第一次抓 case 0 和 case 8 我把它们标反了。`B.NE/B.EQ` 的真实跳向不能凭"块出现的物理顺序"猜，必须沿派发树走。`0xDB4DD48` 是从 `B.NE loc_DB4DD48`（`case_id != 4` 之后又 `!= 5/6/7`）落进来的——也就是 `case_id == 0`；`0xDB4D910` 才是 `case_id == 8` 的位置。后来从两个块各自的 `EOR W8, W20, #imm` 立即数（`#0x40` vs `#0xC`）反查表，对照标准 FName 实现里 case 0 通常用 `^ 0x40` 这种"魔术比特"，确认了顺序。

### 3.3 异或顺序：`EON` vs `EOR + MVN`

NEON 路径都是这种二连：

```asm
EOR  V1.16B, V0.16B, V1.16B    ; V1 = src ^ key
MVN  V1.16B, V1.16B            ; V1 = ~V1
```

但**短数据回退**到标量循环时只有一条：

```asm
EON  W11, W8, W11              ; W11 = W8 XOR (NOT W11) = ~(W8 ^ W11)
```

`EON Wd, Wn, Wm` = `Wn ^ (~Wm)` = `~(Wn ^ Wm)`，所以两条路径**数学等价**。这一点必须验，否则 C++ PoC 用 `~(src ^ k)` 还是 `(src ^ k) ^ 0xFF` 还是 `~src ^ k` 都会写出不同形式，看起来正确实则会因为优先级和位宽问题翻车。

### 3.4 NEON 三档边界

每个 case 末尾的边界判断是这样：

```asm
CMP    W23, #0x200          ; header < 0x200 (len ≤ 7)         → 标量 EON 逐字节
B.CC   loc_xxx_scalar
CMP    W23, #0x400          ; 0x200 ≤ header < 0x400 (8≤len≤15) → 8B NEON
B.CC   loc_xxx_8b
                            ; header ≥ 0x400 (len ≥ 16)         → 16B NEON + 8B + 标量余数
DUP    V0.16B, W8
AND    X10, X9, #0x3F0      ; 16 字节对齐切片
LDR    Q1, [X11]
EOR    V1.16B, V0.16B, V1.16B
MVN    V1.16B, V1.16B
STR    Q1, [X11], #0x10
```

判别量是 `header` 本体（不是 `len`），但 `is_wide=0` 时 bit0 总是 0，bits 1..5 这版未用，所以低 6 位恒为 0，等价于按 `len` 切：

| header 区间 | len 区间 | 路径 |
|---|---|---|
| `< 0x200` | `≤ 7` | 标量 `EON` |
| `0x200..0x3FF` | `8..15` | 8B NEON |
| `≥ 0x400` | `≥ 16` | 16B NEON + 余数 |

边界值不影响解密结果，只影响性能。但一开始我误把"小数据走 NEON、大数据走标量"——正好反了——验证时要拿一个 `len < 8` 的样本（比如 `"None"` 长度 4）才能跑到标量分支证伪。

### 3.5 `is_wide=1` 跳出局：宽路径是另一份算法

走完 9 个 case 自以为搞定了，结果验 `len % 9 == 0` 且 `is_wide == 1` 的样本时（比如 `"DefaultEngine"` 那种本地化字符串），密文怎么解都是乱码。回头看入口：

```asm
db4d490  TBNZ   W23, #0, loc_DB4DCC0   ; ★ is_wide=1 时直接跳走，不进 9-case
```

跳到 `0xDB4DCC0` 后：

```asm
db4dcc0  LSR    X9,  X23, #5             ; len*2 (粗算)
db4dcc4  ADD    X0,  SP, #var_808
db4dcc8  MOV    X1,  X8
db4dccc  MOV    W3,  #0x800              ; max_bytes
db4dcd0  AND    X2,  X9, #0x7FE          ; bytes_to_copy = (header>>5) & 0x7FE = len*2 (偶数)
db4dcd4  BL     bounded_memcpy           ; 把密文搬到栈上
db4dcd8  LSR    X20, X23, #6
db4dcdc  ADD    X0,  SP, #var_808
db4dce0  MOV    W1,  W20                 ; 第二个参数 = len（字符数）
db4dce4  BL     sub_E292F10              ; ★ 完全独立的另一个解密函数
```

**整个 9-case 算法被绕过了**。窄路径 PoC 套到宽字符上必然乱码。

### 3.6 宽路径 `sub_E292F10` 的 9 个 case

进 `sub_E292F10` 看 prologue：

```asm
e292f10  MOV    W8,  #0x38E38E39
e292f18  UMULL  X8,  W1, W8
e292f1c  LSR    X8,  X8, #0x21         ; q = (a2 * 0x38E38E39) >> 33
e292f20  ADD    W8,  W8, W8,LSL#3       ; q*9
e292f24  SUB    W9,  W1, W8             ; case_id = a2 % 9
```

——又是 `% 9` 派发，但常数变成了 `0x38E38E39`（更精确的 33-bit 倒数）；而且函数参数 `W1 = a2` 是 `len` 本身（不是 header），因为调用方在 `db4dce0` 已经预先 `LSR X23, #6` 把 len 单独传过来了。

仍然用 `insn_query` 把 `AND/ORR/EOR/MOV` 全部抓下来。这次最大的发现：**只有 3 条 `AND`**（全是循环对齐），但有 **13 条 `ORR W9, W9, #0x7F`** 和 **同样多的 `ADD W9, W9, #0x80`**——也就是说 9 个 case 的 key 收尾**统一都是 `(... | 0x7F) + 0x80`**，没有窄路径的 `& mask` 那一步。

逐 case 抓完表达式：

| case | 块 | 关键序列 | key（无 mask 截断） |
|---|---|---|---|
| 0 | `0xE292FD0` | `AND W8,W1,#0x1F ; ADD W8,W8,W1 ; ORR #0x7F ; ADD #0x80` | `((len & 0x1F) + len \| 0x7F) + 0x80` |
| 1 | `0xE293188` | `MOV W9,#0xDF ; EOR W9,W1,W9 ; ADD W9,W9,W1 ; ORR #0x7F ; ADD #0x80` | `((len ^ 0xDF) + len \| 0x7F) + 0x80` |
| 2 | `0xE293144` | `MOV W9,#0xCF ; ORR W9,W1,W9 ; ADD W9,W9,W1 ; ORR #0x7F ; ADD #0x80` | `((len \| 0xCF) + len \| 0x7F) + 0x80` |
| 3 | `0xE292F9C` | `ADD W9,W1,W1,LSL#5` (len*0x21) `; ORR #0x7F ; ADD #0x80` | `(len * 0x21 \| 0x7F) + 0x80` |
| 4 | `0xE293090` | `ADD W9,W1,W1,LSR#2 ; ORR #0x7F ; ADD #0x80` | `((len + (len>>2)) \| 0x7F) + 0x80` |
| 5 | `0xE293104` | `ADD W9,W1,W1,LSL#1 ; ADD #5 ; ORR #0x7F ; ADD #0x80` | `((3*len + 5) \| 0x7F) + 0x80` |
| 6 | `0xE2931CC` | `MOV W9,#5 ; ORR W9,W9,W1,LSL#2 ; ADD W9,W9,W1 ; ORR #0x7F ; ADD #0x80` | `((5 \| (len<<2)) + len \| 0x7F) + 0x80` |
| 7 | `0xE292F50` | `LSR W9,W1,#4 ; ORR #7 ; ADD W9,W9,W1 ; ORR #0x7F ; ADD #0x80` | `(((len>>4) \| 7) + len \| 0x7F) + 0x80` |
| 8 | `0xE293210` | `EOR W8,W1,#0x40 ; ADD W8,W8,W1 ; ORR #0x7F ; ADD #0x80` | `((len ^ 0x40) + len \| 0x7F) + 0x80` |

**和窄路径对照**：case 1/2/3/5/6 的子表达式相同；**case 0/4/7/8 完全不同**。所以工程实现必须分流，不能合并。

异或方式：

```asm
e293160  LDRH  W11, [X0,X8,LSL#1]      ; 加载 16-bit char
e293164  EOR   W11, W11, W9            ; 16-bit XOR
e293168  STRH  W11, [X0,X8,LSL#1]
```

注意 **没有 MVN**！只有 `EOR`。这跟窄路径的 `EOR + MVN` 完全不同。

至于"既然窄路径有 MVN 宽路径没有，是不是不等价"——其实数学上**对低 8 字节**等价：`(value | 0x7F) + 0x80` 在低 8 位等于 `~value & 0x80` 后再随进位翻转，再异或后再异或 `0xFF` = MVN 效果一致。但宽路径用整 16 位 key 异或整 16 位 char，**高 8 位的运算窄路径里根本没做**（窄路径只有 8 位）。所以两条路径只对低字节等价、对高字节是两套完全不同的混淆。

### 3.7 用两个候选方案做交叉验证

抓完 9-case 表之后总担心是不是漏看了什么——比如说有没有可能整个 9-case 其实只是某个简化形式，真正的解密在另外一处。为了证明这一点，我自己先草拟了两个**完全不同思路**的候选实现，再用 IDA 反过来验证哪个跟 .so 的实际行为一致：

**候选方案 A**——「全局密钥 + NEON 广播」：

> 假设有一个全局密钥变量（启动时通过别的算法算出来），把它的低 8 位读出来当 key，用 `vdupq_n_u8` 扩成 16 字节向量，然后对整段密文做 NEON 异或。这是另一些 UE4 项目（包括我之前看过的某 FPS 手游）常见的做法。

**候选方案 B**——「逐字节异或 + 哨兵早退」：

> 假设没有 NEON 路径，就是个简单的标量循环：`for(i){ if(buf[i]==0||buf[i]==key) break; out[i] = buf[i] ^ key; }`。读到 0 或哨兵就提前结束。这种写法在做"FString 字面量解密"的项目里也常见。

如果方案 A 是对的，应该能在 .so 里看到这两个特征：

1. 一处固定的全局地址被 `ADRP/ADRL` 取地址、`LDR W..., [..]` 读出 1 字节；
2. **`key_byte * 0x0101010101010101ULL`** 的 64 位扩展模式——要么以 `MOV W?, #0x01010101 ; MOVK W?, #0x0101, LSL#16` 的二条装载出现，要么这个 64 位常量落在 `.rodata`。

用 IDA `find` 搜 immediate `16843009 (0x01010101)` 与 `72340172838076670 (0x0101010101010101)` ——**两个都搜不到**。再用 `insn_query` 全库拉所有 `DUP V?.16B, W?` 的指令，过滤掉 `fn: null`（数据被误反汇编的部分），剩下能确认在已识别函数内的，**全部都在 `FName_CompareEntryChars` 与 `sub_E292F10` 这两个函数体内**。

换句话说，整个 .so 里没有"在某个固定全局地址读单字节 key、然后 NEON 广播"的代码模式。**方案 A 不成立。**

方案 B 的核心是「单字节 EOR 循环 + 一条 CMP early break」——也就是说应该有一个函数，结构是 `LDRB → CBZ/CMP → EOR → STRB → SUBS → B.NE`。我对潜在的字符串解密器（按 entry 字节读取的下游函数）做这个指纹的查询，没有匹配上。**方案 B 也不成立。**

由此反向佐证：**这版样本的 FName 解密就是 9-case 现算 key + EON/EOR**，没有"全局密钥"，也没有"哨兵早退"。这两个候选方案在我熟悉的其它项目里都见过类似形态，但这一份样本就是不一样——`key` 完全由 `len/header` 现场派生，整个算法是「自包含」的，不依赖任何运行时全局状态。

这一步看起来"啥也没找到"，但它的价值在于：**排除了"我可能漏掉一个真正的解密器"这个怀疑**。后面写工程代码时心里就踏实了——9-case 是唯一的解密路径。

### 3.8 小结：算法逆向的方法论

整段算法逆向其实没什么"一击必中"的诀窍，只是分四步走：

1. **找派发轴**：见到 `0x1C72`/`0x38E38E39`/`0xAAAAAAAB` 这种魔术常数立即认出是无除法取模；
2. **抓 mask 表**：用 `insn_query` 列出所有 `AND Wd, Wd, #imm`，剔除循环对齐用的 `0x3F0`/`0x3F8`，剩下的就是 case mask；
3. **倒推子表达式**：从每条 mask 往上读 5–10 行，注意区分 key 计算（`MOV/EOR/ORR/ADD`）和循环长度计算（带 `CSINC/CSEL`）；
4. **验等价性**：`EON` ≡ `EOR + MVN`，`(x | 0x7F) + 0x80` 在低位 ≡ `~x & 0x80` 翻转，事先把这些代数恒等式在脑子里准备好，否则会在"明明都是异或为什么写出来不一样"上来回纠结。

整个 0x3 节的工作产物：**两份独立、可逐字节复现的 PoC**（窄/宽），mask 与表达式逐 case 对应到具体 IDA 地址，工程实现只要按 `header & 1` 分流即可。完整代码见 0x6 节。

## 0x4 一个静态文件层面的小观察

回到 .so 静态文件层面有一个有意思的事实：所有 UE4 反射元数据 token —— `"ByteProperty"`、`"StaticClass"`、`"ObjectProperty"`、`"StructProperty"`、`"XGameViewportClient"` 等等 —— 在 `.rodata` 里是**明文**，而且 ASCII 和 UTF-16 各存一份：

```
0x1795219:  42 79 74 65 50 72 6F 70 65 72 74 79 00       "ByteProperty\0"
0x2D7F7D8:  42 00 79 00 74 00 65 00 50 00 72 00 6F 00 70  "B.y.t.e.P.r.o.p"
```

加密只发生在**运行时 FNamePool 内的 FNameEntry** 字符体上——这些明文字面量在程序启动时被 `LookupOrAdd` 拿到，先用 9-case 算法生成密文，再写到 GMalloc 分配的 stringPool 里。所以静态 dump 这个 .so 不会看到密文版的 FName，只能在运行内存里抓到。

这一条对做 SDK dumper 也有意义：如果你要的只是反射类型名，**直接读 .rodata 就好**，根本不需要解密。只有反查"FName.Index → 字符串"这条路才必须跑 9-case。

## 0x5 第四轮：FName index → entry 地址

到这一步，要把所有东西串成"给我一个 NameId、还我一个明文字符串"的链路。

### 5.1 该样本的 NameId 是什么

UE4 4.25 之前的经典 FName 实现里，`FName.ComparisonIndex` 是 32 位**packed handle**，编码方式从 `LookupOrAdd` 的写入路径反推：

```asm
db49da4  ADD   X8, X22, X26, LSL#3       ; arena[chunkIdx]
db49dac  LSL   W10, W26, #0x12           ; chunkIdx << 18
db49db4  AND   X9,  X25, #0xFFFFFFFE     ; cursor & ~1
db49db8  LDR   X8,  [X8, #0x38]          ; chunkPtr = arena[chunkIdx].slot+0x38
db49dbc  ORR   W22, W10, W25,LSR#1       ; handle = (chunkIdx<<18) | (cursor>>1)
db49dc0  ADD   X8,  X8, X9               ; entryAddr = chunkPtr + (cursor & ~1)
```

读取路径互证：

```asm
db49e3c  AND   X9, X8, #0x80000000        ; bit31 = case-sensitive 标志
db49e48  LDR   X9, [X20, #0x48]           ; arena = bucket->entryArena
db49e4c  UBFX  X10, X8, #0x12, #0xD       ; chunkIdx = (handle >> 18) & 0x1FFF
db49e50  ADD   X9, X9, X10, LSL#3         ; slotAddr = arena + chunkIdx*8
db49e58  LDR   X8, [X9, #0x38]            ; chunkPtr = *(uintptr*)(slotAddr + 0x38)
db49e5c  UBFIZ X9, X10, #1, #0x12         ; entryByteOff = (handle & 0x3FFFF) << 1
db49e60  LDRH  W10, [X8, X9]              ; header = *(u16*)(chunkPtr + entryByteOff)
```

`UBFIZ Xd, Xn, #1, #0x12` 是 ARM64 的 bitfield insert：取 W10 的低 18 位左移 1 位填进 X9。所以正确公式是：

```
chunkIdx     = (handle >> 18) & 0x1FFF              // 13 位
entryByteOff = (handle & 0x3FFFF) << 1               // 18 位 << 1
slotAddr     =  arenaBase + chunkIdx * 8
chunkPtr     = *(uintptr_t*)(slotAddr + 0x38)        // ★ +0x38 才是真 chunkPtr
entryAddr    =  chunkPtr + entryByteOff
bit31        =  case-sensitive 标志（仅查找用，不参与寻址）
```

`+0x38` 这一条是该版 arena 的特殊布局——常规教科书是「指针数组 stride 8」，这里 stride 也是 8，但 8 字节槽里 `+0x38` 处才是真正的 chunkPtr。盲套通用公式会读到一个完全不可解的地址。

### 5.2 4.25+ FNamePool 公式不能用

网上流传的 dumper 大多是这样：

```cpp
unsigned int Block  = NameId >> 16;
unsigned short Off  = NameId & 0xFFFF;
auto Chunk = Read<uintptr_t>(FNamePool + 0x40 + Block * 8);
uintptr_t Entry = Chunk + Off * 2;
```

这是 UE4 4.25+ `FNamePool` 的布局，该样本**不适用**。因为：

- 该样本是 16 个固定 hash 桶，不是按 block 索引的 chunk 数组；
- `+0x40` 在该版本里不是 chunk 表起点，而是 bucket 内的 `hashTable` 指针;
- 该样本的 NameId 是 packed handle，`>>16` 拿不到 block，`&0xFFFF` 拿不到 offset；
- 即使 entry 地址恰好对了，里面是密文，直接当 ASCII 读会乱码。

要适配这版的话必须重写。

### 5.3 "从 NameId 现场反查"为什么不可行

正常想法：拿 NameId → 算桶号 → 在 `hashTable[mask+1]` 里查 idx → 拿 handle → 解地址。

问题是该样本选桶用的是 `hash64 & 0xFFFFFFFF`（hash 的低 32 位），而 `NameId` 在这版 UE 里**只承载 packed handle**，不携带 hash 信息。也就是说，光给一个 NameId，**没法知道它属于哪个桶**。除非把所有 16 个桶的 hashTable 都过一遍才能匹配——现场反查每次都做一次 16 桶大扫，效率不可接受。

### 5.4 工程方案：启动时建一次缓存

该样本的 `FNameEntry` 实体一旦插入，地址在生命周期内不变。所以一次扫遍 16 桶 × 整张 hashTable，把 `(handle → 解密后的明文)` 建成 `unordered_map`，之后查询 O(1)：

```cpp
for (size_t b = 0; b < 16; ++b) {
    bucket = pool + 0x10080 + b * 0x80;
    mask    = Read<uint32_t>(bucket + 0x3C);
    hashTbl = Read<uintptr_t>(bucket + 0x40);
    auto tbl = ReadArray<uint32_t>(hashTbl, mask + 1);
    for (uint32_t handle : tbl) {
        if (!handle) continue;
        uintptr_t entry = EntryAddrFromHandle(bucket, handle);
        cache[handle & 0x7FFFFFFF] = ReadDecryptEntry(entry);
    }
}
```

实测一份样本启动后 entry 数量在 80k–200k 之间，建表不到 1 秒。

## 0x6 完整最终代码

下面这份是落在工程里可直接编译的（依赖工程的 `XY_TRead<T>` 与 `ReadAddr`）：

```cpp
namespace XGame {

constexpr uintptr_t kFNamePoolModuleOffset = 0x1BB53A80;
constexpr uintptr_t kPool_BucketsBase      = 0x10080;
constexpr size_t    kBucketStride          = 0x80;
constexpr size_t    kBucketCount           = 16;
constexpr size_t    kBucket_HashMask       = 0x3C;
constexpr size_t    kBucket_HashTablePtr   = 0x40;
constexpr size_t    kBucket_EntryArenaPtr  = 0x48;
constexpr size_t    kArenaSlotStride       = 8;
constexpr size_t    kArenaSlotChunkPtr     = 0x38;

constexpr uint32_t kHandleEntryMask  = 0x3FFFFu;
constexpr uint32_t kHandleChunkShift = 18;
constexpr uint32_t kHandleChunkMask  = 0x1FFFu;
constexpr uint32_t kHandleIndexMask  = 0x7FFFFFFFu;

uintptr_t g_FNamePool = 0;
inline void InitFNamePool(uintptr_t libUE4Base) {
    g_FNamePool = libUE4Base + kFNamePoolModuleOffset;
}

inline void DecryptNarrow(uint8_t* buf, uint16_t header) {
    const uint32_t len = (uint32_t)(header >> 6);
    if (len == 0 || buf[0] == 0) return;
    uint32_t key = 0;
    switch (len % 9u) {
    case 0: key = ((len ^ 0x40u)              + len)               & 0x0780u; break;
    case 1: key = (((header >> 6) ^ 0xDFu)    + len)               & 0x0780u; break;
    case 2: key = ((len | 0xCFu)              + len)               & 0x0780u; break;
    case 3: key = ((header >> 6) * 0x21u)                          & 0xFF80u; break;
    case 4: key = ((header >> 8)              + (header >> 6))     & 0x0780u; break;
    case 5: key = (3u * len + 5u)                                  & 0x1F80u; break;
    case 6: key = ((5u | (len << 2))          + len)               & 0x1F80u; break;
    case 7: key = (((header >> 10) | 7u)      + (header >> 6))     & 0x0780u; break;
    case 8: key = ((len ^ 0x0Cu)              + len)               & 0x0780u; break;
    }
    const uint8_t k = (uint8_t)key;
    for (uint32_t i = 0; i < len; ++i)
        buf[i] = (uint8_t)~(buf[i] ^ k);
}

inline void DecryptWide(uint16_t* buf, uint32_t len) {
    if (len == 0 || buf[0] == 0) return;
    uint32_t key = 0;
    switch (len % 9u) {
    case 0: key = ((len & 0x1Fu)         + len);              break;
    case 1: key = ((len ^ 0xDFu)         + len);              break;
    case 2: key = ((len | 0xCFu)         + len);              break;
    case 3: key = (len + (len << 5));                          break;
    case 4: key = (((len >> 4) | 7u)     + len);              break;
    case 5: key = (3u * len + 5u);                             break;
    case 6: key = ((5u | (len << 2))     + len);              break;
    case 7: key = (len + (len >> 2));                          break;
    case 8: key = ((len ^ 0x40u)         + len);              break;
    }
    key = (key | 0x7Fu) + 0x80u;
    const uint16_t k = (uint16_t)key;
    for (uint32_t i = 0; i < len; ++i) buf[i] ^= k;
}

uintptr_t EntryAddrFromHandle(uintptr_t bucketBase, uint32_t handle) {
    handle &= kHandleIndexMask;
    if (!handle) return 0;
    const uint32_t  chunkIdx     = (handle >> kHandleChunkShift) & kHandleChunkMask;
    const uint32_t  entryByteOff = (handle & kHandleEntryMask) << 1;
    const uintptr_t arenaBase = XY_TRead<uintptr_t>(bucketBase + kBucket_EntryArenaPtr);
    if (!arenaBase) return 0;
    const uintptr_t slotAddr = arenaBase + (uintptr_t)chunkIdx * kArenaSlotStride;
    const uintptr_t chunkPtr = XY_TRead<uintptr_t>(slotAddr + kArenaSlotChunkPtr);
    if (!chunkPtr) return 0;
    return chunkPtr + entryByteOff;
}

std::string ReadDecryptEntry(uintptr_t entry) {
    if (!entry) return "None";
    uint16_t header  = XY_TRead<uint16_t>(entry);
    bool     is_wide = (header & 1u) != 0;
    uint32_t len     = (header >> 6) & 0x3FFu;
    if (len == 0 || len >= 250) return "None";
    if (!is_wide) {
        std::vector<uint8_t> raw(len);
        if (!ReadAddr(entry + 2, raw.data(), len)) return "None";
        DecryptNarrow(raw.data(), header);
        return std::string((char*)raw.data(), len);
    } else {
        std::vector<uint16_t> raw(len);
        if (!ReadAddr(entry + 2, raw.data(), len * 2)) return "None";
        DecryptWide(raw.data(), len);
        // Utf16ToUtf8 略，BMP 区段三段式
        std::string s; s.reserve(len);
        for (uint32_t i = 0; i < len; ++i) {
            uint16_t c = raw[i];
            if (c < 0x80)        s.push_back((char)c);
            else if (c < 0x800)  { s.push_back((char)(0xC0|(c>>6))); s.push_back((char)(0x80|(c&0x3F))); }
            else                 { s.push_back((char)(0xE0|(c>>12))); s.push_back((char)(0x80|((c>>6)&0x3F))); s.push_back((char)(0x80|(c&0x3F))); }
        }
        return s;
    }
}

static std::unordered_map<uint32_t, std::string> g_FNameCache;

void BuildFNameCache() {
    g_FNameCache.clear();
    g_FNameCache.reserve(0x100000);
    for (size_t b = 0; b < kBucketCount; ++b) {
        const uintptr_t bucket = g_FNamePool + kPool_BucketsBase + b * kBucketStride;
        const uint32_t  mask    = XY_TRead<uint32_t>(bucket + kBucket_HashMask);
        const uintptr_t hashTbl = XY_TRead<uintptr_t>(bucket + kBucket_HashTablePtr);
        if (!hashTbl || !mask) continue;
        std::vector<uint32_t> tbl(mask + 1);
        if (!ReadAddr(hashTbl, tbl.data(), (mask + 1) * 4)) continue;
        for (uint32_t handle : tbl) {
            if (!handle) continue;
            uint32_t key = handle & kHandleIndexMask;
            if (g_FNameCache.count(key)) continue;
            uintptr_t entry = EntryAddrFromHandle(bucket, handle);
            if (!entry) continue;
            std::string name = ReadDecryptEntry(entry);
            if (!name.empty() && name != "None")
                g_FNameCache.emplace(key, std::move(name));
        }
    }
}

std::string GetName(uint32_t NameId) {
    auto it = g_FNameCache.find(NameId & kHandleIndexMask);
    return it != g_FNameCache.end() ? it->second : "None";
}

} // namespace XGame
```

## 0x7 难点回顾

把整个过程的"卡点"列出来，留给后人翻类似样本时少走弯路：

1. **先入为主把 LTO 当混淆**。任何 90KB 以上的单函数都让人想到 OLLVM。但 ARM64 + Clang LTO + 全 unroll 完全能产生这种体积。判别套路：所有"opaque predicate"先看 bss 字节是不是 `__cxa_guard`，所有"绕路块"先看 BL 跟到的地方是不是异常重入 trampoline，所有"dispatcher"先看是不是 stack canary check + RET。
2. **`g_FNamePool` 的指针 vs 实体**。代码里用 `ADRL` 直接拿地址、不解引用，意味着这是结构体本体；如果是指针变量会先 `LDR Xn, [Xn]`。这一条搞错的话，拿到的"chunk 指针"会指向 stringPool 的那个 GMalloc 块里去，立刻乱。
3. **9-case mask 不能省**。流传的 PoC 把 `& 0x780/0x1F80/0xFF80` 写成 `& 0x000`，看起来好像异或不掉就是这个原因。每个 case 的 mask 必须从对应分支里的 `AND W8, W8, #imm` 抓——case 用 `B.LE/B.NE/B.EQ` 不严格按 0..8 顺序排列，需要按特征指令对位。
4. **窄/宽路径不能合并**。is_wide=1 时 `FName_CompareEntryChars` 把控制流交给 `sub_E292F10`，那是另一份 9-case 算法，常量、收尾、是否取反都不同。把窄路径硬套到 16-bit 字符上会出乱码。
5. **该样本的 NameId 不能现场反查地址**。它是 packed handle，不携带 hash。要么扫 16 桶建缓存（推荐），要么放弃靠 NameId 现场解决。
6. **arena chunk 表的 `+0x38`**。这不是 UE 标准布局，是该版本的特殊布局——chunkPtr 不是直接放在 arena 槽起点，而是槽内 +0x38 处。盲套通用公式会读出非堆地址。

## 0x8 总结

整个 PoC 跑下来是这样的链路：

```
模块基址 + 0x1BB53A80 = g_FNamePool
                     │
                     ├── +0x10080 + i*0x80 = bucket[i]   (i ∈ [0,16))
                     │                  │
                     │                  ├── +0x3C  hashMask
                     │                  ├── +0x40  hashTable[mask+1]  (uint32 handles)
                     │                  └── +0x48  arena
                     │                              │
                     │                              └── +chunkIdx*8 + 0x38 = chunkPtr
                     │                                                │
                     │                                                └── +entryByteOff = entry
                     │                                                                  │
                     │                                                                  ├── header (u16, bit0=is_wide, bits6..15=len)
                     │                                                                  └── 密文字节
                     │
                     └── 解密 = 9-case 异或 + (窄路径 ~ / 宽路径 (|0x7F)+0x80)
```

最后给当时被打脸的自己几条建议：

- 先看 helper 函数身份再下混淆判断；
- ARM64 上 16/8 字节 NEON + 标量回退的三档路径几乎都是性能优化，不是混淆；
- 如果 `LDR Xn, [bss_addr_aligned_8]` + `BL` 很短，去看那条 BL 是不是 PLT 跳板、目标是不是 libc++ 的 `__cxa_guard_*`；
- 任何"看起来像 dispatcher 的块"都先 `MRS X?, TPIDR_EL0; LDR X?,[X?,#0x28]` 找 stack canary，找到了基本就是 epilogue。

整个分析过程使用 IDA Pro + IDA MCP 完成，全程不依赖反编译伪码——汇编 + helper 身份匹配足以走完。这份样本最终落到内存 dumper 里，能稳定从 `FName.ComparisonIndex` 反查到 `"ByteProperty"` `"XGCharacterMovementComponent"` 等等所有反射元数据 token 的明文。
