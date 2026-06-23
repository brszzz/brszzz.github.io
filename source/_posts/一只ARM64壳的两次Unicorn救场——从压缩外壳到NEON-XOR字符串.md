---
title: 压缩壳静态脚本脱取和NEON-XOR字符串解密分析
date: 2026-06-23 20:16:00
tags:
  - ARM64
  - Unicorn
  - NEON
  - XOR
  - 脱壳
  - 字符串解密
  - ELF
  - 逆向工程
  - Capstone
  - LZ77
  - SIMD
categories:
  - 逆向工程
description: 同一把刀削两层皮。Phase 1 用 Unicorn 模拟脱掉自解压外壳拿到原 ELF，Phase 2 再用 Unicorn 把里面 800+ 处 NEON XOR 字符串混淆全捞出来。两阶段共 450 行 Python，75 秒完成。
---

# 压缩壳静态脚本脱取和NEON-XOR字符串解密分析

> 同一把刀,削两层皮。先用 Unicorn 模拟脱掉自解压外壳拿到原 ELF,再用 Unicorn 模拟把里面 800+ 处 NEON XOR 字符串混淆全捞出来。两阶段开发日记。

## 起点:一个看着挺干净的 ELF

到手的样本是个 ARM64 ELF,**3.7 MB**,扔进 IDA 一看就觉得不太对劲:

```
Total functions:  7
Named functions:  2
Imports:          0
Strings (clean):  几乎没有
```

7 个函数支起 3.7 MB 的程序?这种"函数数极少 + 导入表空"的形态,基本就是**自解压外壳**的标志。

Program Headers 也有意思:

```
LOAD  0x000000 – 0x94d978   rw   ← 13 MB 大段可读可写(memsz 13MB,filesz 4KB)
LOAD  0x950000 – 0xce4671   rx   ← 真正的 loader 代码
Entry: 0xce3b4c
```

第一段 `memsz` 比 `filesz` 大几个数量级——典型的"运行时填充"。第二段是 stub 代码。整个程序的 entry `0xce3b4c` 就指向 stub 里某处。

数据段(0x000000 起 13MB)就是**压缩负载**,运行时被 stub 解压填充到对应虚拟地址。

## Phase 1:把外壳剥了

### 先看清 loader 在干啥

IDA 把 7 个函数粗看一遍:

- `start @ 0xce3b4c` — 主循环,大量条件分支 + 比特操作
- `sub_CE3BFC` — 短小精悍,4 条指令:`adds w4,w4,w4; cbz w4,refill; ldr w4,[x0],#4; adcs w4,w4,w4` —— 经典的 **bit-stream reader**(range coder / 算术编码)
- `sub_CE3DAC` — 单条 `svc #0`,`w8 = 222 (mmap)` —— mmap syscall wrapper
- `sub_CE3DC0` — 调 mmap,然后 `svc #0` with `w8 = 226 (mprotect)` —— mmap + mprotect 包装
- `sub_CE3E50` — `while(*p++);` —— 扫 auxv 找 NULL 终止符
- 其它两个是 thunk / nullsub

把 `start` 的反汇编草草过一遍,关键模式浮现:

```asm
0xce3c14: ldrb w3, [x0], #1      ; literal byte read
0xce3c18: strb w3, [x2], #1      ; literal byte write
0xce3c1c: bl   sub_CE3BFC         ; read 1 bit
0xce3c20: b.cs literal_loop       ; flag = literal mode
...
0xce3cbc: ldrb w3, [x2, w5,sxtw] ; back-reference copy
0xce3cc0: strb w3, [x2], #1      ; (LZ77-style match)
```

这是经典的 **LZ77 + bit-stream**——字面字节穿插回溯匹配。具体格式跟 aPLib / LZSS / UPX-NRV 一脉相承。

最后还有一段 ARM64 特有的尾巴:

```asm
0xce3b88: mrs   x3, CTR_EL0       ; 读 cache line size
0xce3ba8: sys   #3, c7, c11, #1, x2   ; IC IVAU - invalidate I-cache
0xce3bd8: sys   #3, c7, c5, #1, x0    ; DC CVAU  - clean D-cache
0xce3be8: dsb   ish
0xce3bec: isb
```

**完整的指令缓存刷新流程**——告诉 CPU "刚才写到内存里的字节是新代码,别再用之前的翻译块"。这是自修改代码 (SMC) 的标配,基本坐实了"runtime unpacking + jump to new code"的玩法。

### 决定路径:Unicorn 模拟,在 mprotect 处 dump

手撕 LZ 解码器理论上也能做(算法就那么几十行),但有几个原因让我直接选 Unicorn:

- 不知道 LZ 变种的精确细节,翻译错一个分支就全错
- 解压目标地址、长度、内存布局都是 stub 动态决定的——静态推算容易遗漏
- Unicorn 处理 ARM64 自修改代码有现成 API
- 反正 syscall 才 3 个,hook 起来不费事

**核心思路**:让 Unicorn 把 stub 跑起来,等它 `mprotect(addr, size, RX)` 的时候,把那块内存 dump 出来就完事了——这是壳必须暴露的最大破绽。

### 把 ELF 喂给 Unicorn

按原 ELF 的两个 PHDR 映射进 Unicorn 内存:

```python
# LOAD 1: vaddr 0..0x94d978  (RW, 压缩数据 + 解压目标)
# LOAD 2: vaddr 0x950000..   (RX, loader 代码)
for (off, va, fsz, msz, flags) in PHDRS:
    safe_map(va, msz, UC_PROT_ALL)
    uc.mem_write(va, ELF[off:off+fsz])
```

栈得自己造。Loader 启动时会走 `auxv` 找 `AT_PAGESZ`(`sub_CE3E50` 那个 `while(*p++)` 就是扫两次 NULL 跳过 argv 和 envp 落到 auxv),所以必须伪造完整的 SysV ARM64 程序启动栈:

```
[argc=1]
[argv[0] → "./a"]  [NULL]
[envp NULL]
[auxv:  6 (AT_PAGESZ), 0x1000]
[auxv:  25 (AT_RANDOM), some_addr]
[auxv:  0, 0]
```

### Hook 三个 syscall

```python
def hook_intr(uc, intno, _):
    x8 = uc.reg_read(UC_ARM64_REG_X8)
    if x8 == 56:    # openat
        # /proc/self/exe → 返回伪 fd 3,关联到原文件内容
        uc.reg_write(UC_ARM64_REG_X0, 3)
    elif x8 == 222: # mmap
        size = up(uc.reg_read(UC_ARM64_REG_X1))
        addr = heap_alloc(size)
        uc.mem_map(addr, size, UC_PROT_ALL)
        uc.reg_write(UC_ARM64_REG_X0, addr)
    elif x8 == 226: # mprotect
        # 关键:这是解压完成的信号!
        addr = uc.reg_read(UC_ARM64_REG_X0)
        size = uc.reg_read(UC_ARM64_REG_X1)
        if prot & PROT_EXEC:
            log_unpacked_region(addr, size)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.ctl_remove_cache(addr, addr + size)   # TB cache 失效
```

`pread`、`read`、`close`、`lseek` 这些也都模拟一下,统一返回原 ELF 内容。

### 三个非常实用的小知识点

**`MRS X3, CTR_EL0`**:Unicorn 默认返回 `0x8444c004`(typical I/D line=64B,bit28=IDC 已置位)。**正合适**——bit28 = IDC 表示 D-cache 操作走 fast path,后面那一堆 `DC CVAU` 会被 CPU 当成"已经处理过了"跳过。我啥都不用 patch。

**`SYS #3, c7, c11, #1, X2`(IC IVAU)**:这条特权指令 Unicorn 当 NOP 跑掉,完全不报错。同理 `DSB ISH` / `ISB` 也是 NOP,好极了。

**TB cache**:Unicorn 2.x 有 `ctl_remove_cache(start, end)`,在 mprotect 改成 RX 之后必须调一下。否则 `BR X0` 跳到刚写入的解压区时,Unicorn 会用之前对那块内存的翻译块(stale TB)——直接跑飞。这是真的会坑你 30 分钟的小细节。

### 停机时机的选择

最早我想用 `BR X0`(stub 跳到原 ELF 入口)做停机点,结果发现 stub 是**两阶段**的:

- 第一阶段:解出一个 2.7 KB 的"二级 trampoline"到内存某处,mprotect RX
- 跳过去,二级 trampoline 真的去解整个原 ELF(分 4 个 sub-mmap)
- 解完之后**又开始走 linker64 模拟流程**——尝试重新 dlopen /proc/self/exe

如果等所有阶段跑完才停,内存里就被搞乱了。最干净的时机是:**第二次 `openat(/proc/self/exe)` 触发的瞬间**——此时所有压缩数据已经解完到位,但还没开始做重定位污染。

```python
if path == "/proc/self/exe":
    SECOND_EXE_OPEN += 1
    if SECOND_EXE_OPEN == 2:
        dump_final_elf()    # 把所有 mmap 区拼成完整 ELF
        uc.emu_stop()
```

### Dump 出来的 ELF 有个小问题

把 stub 解压填的 4 块 mmap 拼起来,作为完整 ELF 一看:

```
$ xxd unpacked.bin | head -1
00000000: ffff ff46 0201 0100 0000 0000 0000 0000
```

ELF magic 是 `FF FF FF 46` —— 不是 `7F 45 4C 46`!

回查 stub 代码,找到了:`0xce3e10: STR X26, [X27]` —— 解压完之后 stub **故意把 ELF magic 写坏 8 字节**。具体是因为 stub 的解压目标缓冲区会被它自己的元数据覆盖头几个字节。

补 magic 就完事了:

```python
fixed = b"\x7fELF" + data[4:]
```

`file` 一跑:`ELF 64-bit LSB shared object, ARM aarch64, dynamically linked, interpreter /system/bin/linker64`。9.3 MB,**直接可以扔 IDA**。

### 复盘第一阶段

| 项目 | 数据 |
|---|---|
| Unicorn 脚本行数 | ~250 |
| 模拟时长 | ~60 秒 |
| Hook 的 syscall 数 | openat / read / pread64 / mmap / mprotect / close / lseek / brk / set_tid_address / futex / exit |
| 解出物 | 9,755,000 字节 ELF + 2,664 字节 stage-0 trampoline |
| 关键 trick | mprotect RX 时 `ctl_remove_cache`、`/proc/self/exe` 二次打开时停机 |

## Phase 2:strings 一上手就傻了

剥完外壳拿到 9.3 MB 的 ARM64 ELF,以为终于能干净地分析了。`strings` 扫一遍——除了几个 libc 符号名、`vkXXX`、`ImGui` 之类的库自带串,**几乎抓不到任何业务字符串**。

这就有意思了。一个有 GUI、有网络、有交互逻辑的程序,菜单文本、URL、协议字段全跑哪去了?

不死心,在 IDA 里随便挑了个函数翻翻,看到这样的画面:

```asm
0x34b520: mov   x9,  #0x2140
0x34b524: mov   x23, #0x69c4
0x34b528: mov   x19, #0x7a5b
0x34b530: movk  x9,  #0x454c, lsl #16
0x34b534: movk  x23, #0xc0d0, lsl #16
0x34b538: movk  x19, #0x707f, lsl #16
0x34b540: movk  x9,  #0xdc1,  lsl #32
0x34b544: movk  x23, #0x5937, lsl #32
0x34b548: movk  x19, #0x3cfa, lsl #32
0x34b54c: movk  x9,  #0x2024, lsl #48
0x34b550: movk  x23, #0x98c4, lsl #48
0x34b554: movk  x19, #0x2049, lsl #48
...
0x34b570: ldr   q0, [sp, #0x780]
0x34b578: ldr   q1, [x8]
0x34b580: eor   v0.16b, v1.16b, v0.16b
0x34b584: str   q0, [sp, #0x780]
```

一片 `MOV+MOVK×4` 组合,然后 NEON 一次 XOR。

哦——**字符串根本不在 .rodata 里**,而是被拆成 16 字节一组,用立即数装配出"密文"和"key",运行时往栈上一推、`eor v0.16b, v1.16b, v0.16b` 一拍就出来了。

这种保护方式在 Windows 加固的 stub 里见过。在 ARM64 上看到 NEON 版本还挺新鲜——一条 SIMD 指令解 16 字节,效率极高,作者还省了硬编码 key 表。

## 第一招:纯静态正则,挨条算

最直观的思路:既然加解密都靠死板的 `MOV/MOVK + STR + LDR q + EOR`,那我直接静态分析,顺着模式找出来挨条算就行。

写了个第一版,逻辑大概是:

1. Capstone 全量反汇编 .text(215 万条指令)
2. 扫描所有 `eor vX.16b, vY.16b, vZ.16b`,一共 **863 处**
3. 每个 EOR 往前找两条 `ldr q?, [sp, #imm]`,拿到 q0/q1 各自的栈偏移
4. 再往前找填那俩栈槽的 `STR xN, [sp, #imm]`,拿到 4 个 GPR 寄存器名
5. 对每个寄存器,沿基本块往回扫 `MOV/MOVK` 链,拼出 64-bit 立即数
6. 两个 128-bit 值 XOR,strip nulls,UTF-8 解码

跑完——**16 个唯一明文**。包括域名、产品 ID、目标包名前缀那种关键串。

但是……863 个 EOR 里只解出 16 个,这覆盖率有点惨。

## 静态分析的几个坑

挂掉的原因排查下来主要是这几个:

### 坑 1:基本块边界画错了

我一开始把 `bl`(函数调用)也当成基本块边界,认为遇到 BL 就要重置寄存器状态。这是错的——**ARM64 ABI 规定 `x19..x28` 是 callee-saved**,被调函数保证不破坏。而作者偏偏就用这几个寄存器存密文。

修复:`gpr_value_at` 里只对 caller-saved(`x0..x18`、`x30`)在 BL 后重置,callee-saved 跨 BL 继续追。

```python
if ins.mnemonic in ("bl", "blr") and not is_callee_saved:
    if reg_num in tuple(range(0, 19)) + (30,):
        val = None
    continue
```

### 坑 2:栈基址不一定是 sp

代码里大量出现这种"中转":

```asm
add  x8, sp, #0x8e0
str  x19, [x8]
str  x23, [x8, #8]
ldr  q1, [x8]
```

q1 的基址是 `x8`,不是 `sp`。我得回溯 `x8` 最近的 `add x8, sp, #N` 才能解析出真正的栈偏移。

### 坑 3:LDP / STP 一次写两个

```asm
stp  q0, q1, [sp, #0x780]   ; 一次 32 字节
ldp  q0, q3, [x8]           ; 一次读两个 q 寄存器
```

我的正则只匹配单寄存器 `ldr/str`,LDP/STP 一律漏掉。补上对应的解析后又多救回来几个。

### 坑 4:双层 XOR

有些字符串先经过一次 XOR "扰乱"、再 XOR 还原。我的工具只看最后一条 `eor`,中间那一层产生的中间值算不出来。这类需要真正模拟才搞得定。

修补完前三个坑,覆盖率从 1 涨到 24,加上分块拼接后能输出 16 个独立明文。仍然差强人意。

## 第二招:换 Unicorn 直接跑(又一次)

静态正则的天花板已经摸到了——再加补丁也就这样。**第一阶段我们已经验证了 Unicorn 是把好刀,这次接着用。**

思路简单粗暴:

1. 找到每个 EOR 所在函数的入口点
2. 把整个 ELF 镜像映射进 Unicorn(这次是脱壳后的 ELF)
3. 从函数入口跑到 EOR 之后约 16 条指令
4. 跑完去扒栈,看哪里冒出了"刚生成的"字符串

代码框架就 200 多行,关键是把几个坑填了。

### 跳过子函数调用

跑起来肯定要调一堆 libc/Helper 函数——`memcpy`、`strncpy`、PLT stub 啥的。Unicorn 不可能真去执行 libc(也没 libc 装进去),硬跑必崩。

办法:**全局 hook 所有 BL/BLR/SVC,直接当 NOP 跳过,顺手把 x0 设成 0**(模拟"调用返回 0")。

```python
def hook_code(uc, addr, size, _):
    insn = struct.unpack("<I", bytes(uc.mem_read(addr, 4)))[0]
    # BL  → 0x94000000
    # BLR → 0xD63F0000
    # SVC → 0xD4000001
    if (insn & 0xFC000000) == 0x94000000 or \
       (insn & 0xFFFFFC1F) == 0xD63F0000 or \
       (insn & 0xFFE0001F) == 0xD4000001:
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, addr + 4)
        return
    # BR / RET → 函数结束,停机
    if (insn & 0xFFFFFC1F) == 0xD61F0000 or \
       (insn & 0xFFFFFC1F) == 0xD65F0000:
        uc.emu_stop()
```

跳过 libc 这事乍看挺粗暴,但**对解密路径完全无影响**——字符串都是在 EOR 之后立刻生成在栈上,根本不需要 libc 配合。

### 找函数入口

把 .text 全量反汇编后,扫所有疑似 prologue:
- `stp x29, x30, [sp, #-N]!`(经典帧建立,带 pre-index)
- `paciasp`(PAC 序言)
- `sub sp, sp, #N`(无帧但开栈)

二分查找最近的一个 prologue 作为入口。**还找不到就退化**——从 EOR 往前 0x80 / 0x200 / 0x600 / 0x1000 各试一遍,哪个能跑通用哪个。

### 栈基线"差分"识别新字符串

每个函数会用栈做大量临时计算,栈上原本就可能有别的 ASCII 串(比如调用其他函数留下的)。怎么区分"模拟出来的明文"vs "本来就在那的噪声"?

办法:**先空跑一遍打基线,再跑实际逻辑,只保留新出现的字符串**。

```python
# 第一次跑 1 条指令,采集栈基线
reset_stack_and_run(fn, fn + 4, max_insns=1)
baseline = set(s for _, s in scan_stack_for_strings())

# 第二次跑到 EOR 之后,扫栈
reset_stack_and_run(fn, eor_addr + 0x40, max_insns=2000)
for addr, s in scan_stack_for_strings():
    if s in baseline:
        continue   # 基线噪声,忽略
    # 这就是新解出来的明文
```

简单粗暴,但工程上够用。

### Stack 复用 + 寄存器零初始化

每次模拟前要把栈底一段抹零(`b"\x00" * 0x8000`),否则上次的解密结果会污染本次的扫描。寄存器也全归零,只有 `x0` 设个合法栈地址(很多函数把 `x0` 当 `this` 指针用,设零会立刻崩)。

整个 Unicorn 实例复用,只重置必要的状态——一次性 mmap 整个 ELF 进去就行,**863 个 EOR 全跑完一共只要 ~15 秒**。

### 自动拼接相邻 16B 块

> 16 字节一组是个硬约束:大于 16 字符的字符串会被拆成多块。

观察到一个规律:同一个长字符串的几个 16B 块,在代码里的 EOR 地址通常相邻、栈偏移也连续(N、N+16、N+32...)。基于这个简单的启发式:

```python
# 按 EOR 地址排序,相邻 + 栈偏移差 16 的合并
if (nxt.eor_addr - cur.eor_addr <= 0x20
    and nxt.slot1 == cur.slot1 + 16):
    chunks.append(nxt)
```

效果很好——长路径、完整 URL 命令、长免责声明都能完整拼出来。

## 跑完一看,大丰收

15 秒后,日志写:

```
[+] Done. Recovered 62 unique strings
    failures: 7  skipped: 0
```

**62 条独立明文**,从静态版的 16 条翻了将近 4 倍。

随手挑几个有趣的:

| 类别 | 示例 |
|---|---|
| 启动 banner | `欢迎使用 XXX 对接程序.` |
| 版本/作者 | `当前版本 5.1 作者：XXX.` |
| 时间格式 | `%Y-%m-%d %H:%M:%S` |
| 协议字段 | `kami=%s&markcode=%s&t=%d&%s` |
| 系统命令 | `iptables -t nat -A OUTPUT -p tcp -d %s --dport 80 -j REDIRECT --to-port 7777` |
| 路径 | `/proc/%d/mem` 、 `/sys/class/kgsl/kgsl/proc` |
| ANSI 染色 | `\x1b[1;33m...\x1b[0m` |
| 法律话术 | 整段免责声明 |

加密一开就是大瓜——可读性比 strings 高 10 倍。

## 复盘:两次 Unicorn 都用得很爽

回头看,**Phase 1 和 Phase 2 本质是同一招**:

| | Phase 1 脱壳 | Phase 2 解字符串 |
|---|---|---|
| 目标 | 把压缩负载还原成原 ELF | 把 inline XOR 字符串还原成明文 |
| 难点 | LZ 变种 + SMC + cache flush | 16B 块 + 高编号 NEON 寄存器 + 双层 XOR |
| 静态推导 | 算法繁琐,容易漏边角 | 正则覆盖率天花板 16/863 |
| Unicorn 模拟 | hook syscall,在 mprotect 处 dump | hook BL/BLR/SVC,扫栈基线差分 |
| 耗时 | 60 秒 | 15 秒 |
| 脚本规模 | ~250 行 | ~200 行 |

**Unicorn 的几个杀手锏**:

1. **作者所有反静态分析的招都不起作用了。** LZ 变种、双层 XOR、`v4..v31` 高编号寄存器、`stp q0,q1` 联合存储、`add xN,sp,#imm` 间接基址——你怎么混我都不用管,CPU 怎么算结果怎么样。

2. **失败模式可控。** 跑不通的(比如指令越界、访问未映射地址)在 hook 里直接吞掉,不影响其他 EOR 的处理。863 个站点跑下来只有 7 个 failure,全是边角 case。

3. **速度其实不慢。** Unicorn 的 TB cache 在重复跑同一个函数时有命中,实际比想象中快。

4. **代码量比静态版还少。** 静态版我写了 ~250 行复杂的回溯逻辑,Unicorn 版核心只有 ~80 行。

## 几个还没解决的问题

- **失败的 7 个**:大多是函数太复杂、prologue 找不到、或者解密依赖外部内存(比如某个全局变量当 key)。要把这部分也拿下,得给 Unicorn 加更聪明的 mmap 兜底——把 `.rodata`/`.data` 段也按 ELF PHDR 映射好。
- **NEON 矩阵噪声**:863 个 `.16b eor` 里其实只有 60-80 个是字符串解密,剩下的全是图形库的矩阵运算/哈希计算。我现在靠"输出字符串可读性"做了过滤,但偶尔会有"碰巧可读"的假阳性。要真正区分,得反查 EOR 之后是不是被某种字符串-using 调用使用了。
- **长字符串拼接的边界**:启发式拼接对大多数情况 OK,但偶尔会拼错(把两段不相关的串接到一起)。更严格的方案是看 `STR q?, [sp, #N]` 之后是否有"使用 sp+N 起始的整段 buffer"的代码模式。

但这些都属于"完美主义优化"了。62 个明文足够让我把这个壳里的所有业务逻辑看明白,够用了。

## 一点感受

回到一开始那两个问题:

**外壳为什么用自定义 LZ?**

加固/外挂作者爱用 inline LZ packer,是因为它有几个性质:

- **零依赖**:不挂任何运行时,纯 syscall + 一段汇编搞定
- **零静态特征**:导入表为空,函数数极少,IDA 几乎啥都看不见
- **代价低**:解压一次开机付一次代价,后面性能 100% 原生

**字符串为什么用 NEON inline XOR?**

- **零运行时开销**:一条 NEON 指令解 16 字节,跟没加密一样快
- **零静态特征**:`strings`、`grep`、IDA 字符串面板一律抓不到
- **零代码膨胀**:没有 .rodata 表,密文/key 全在指令操作数里

代价是**反汇编可读性极差**——但作者算计的就是:多数人逆向流程会在"`strings` 没干货"这一步弃疗,或者在"函数数太少没法分析"那一步弃疗。

破解之道也很简单——**别静态推,直接让 CPU 帮你算**。Unicorn 这种轻量级 emu 框架本来就是干这个的。哪怕是 SMC、动态 mmap、自定义压缩算法这种听起来吓人的玩意儿,只要你能把 syscall 接口模拟好、能在合适的时机停机 dump,十几秒就能扒得底裤都不剩。

两阶段下来 450 行 Python,15 + 60 = 75 秒。下次再遇到类似套路,直接复用这俩壳就行。

---

*工具:`unpack.py`(脱壳)+ `neon_xor_unicorn.py`(解字符串),都是 Unicorn + Capstone,无任何重型依赖。*
