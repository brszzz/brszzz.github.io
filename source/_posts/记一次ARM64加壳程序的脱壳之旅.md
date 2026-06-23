---
title: 记一次 ARM64 加壳程序的脱壳之旅 —— Unicorn 模拟执行的实战记录
date: 2026-06-23 20:04:00
tags:
  - ARM64
  - Unicorn
  - Virbox
  - 脱壳
  - ELF
  - Android
  - 逆向工程
  - aPLib
  - mprotect
  - 模拟执行
categories:
  - 逆向工程
description: 目标样本为 Virbox Protector 加壳的 ARM64 ELF，使用 Unicorn 模拟执行在 PC 上几秒完成脱壳。本文还原壳的 aPLib/NRV LZ77 解码器、双层加载结构、伪 ELF 魔数等细节，并详述 hook mprotect 作为脱壳信号的核心策略。
---

# 记一次 ARM64 加壳程序的脱壳之旅 —— Unicorn 模拟执行的实战记录

> 目标样本：一个伪装成 shell 脚本、实为 ARM64 ELF、被 **Virbox Protector**（深思数盾）加壳的 Android 程序。大小约 1.2 MB，脱完后真实 payload 大概 864 KB。整个过程在 PC 上几秒钟就能跑完，零真机、零反调试。

---

## 一、这东西是怎么被加壳的

Virbox Protector 这个壳，跟 VMProtect、Themida 之类是同一类产品，只不过它更偏向 Linux / Android native 平台。它对一个二进制能做的事一般分四档：

| 技术 | 干啥用的 |
|---|---|
| 代码加壳/压缩 | 把原始 .text/.data 压成位流，运行时再展开，让你静态反汇编啥也看不见 |
| 代码虚拟化 (VM) | 把关键函数翻译成自定义字节码，脱了壳也只能看见 dispatcher 在跳来跳去 |
| 反调试/反 dump | ptrace 检测、TLS callback、SIGTRAP 自捕获等等 |
| 完整性校验 | CRC / 哈希签名，防止你打补丁 |

这次碰到的样本只开了**第一档——纯自解压壳**，没有反调试也没有虚拟化。换句话说这是相对"轻量"的配置，Virbox 重度模式下会把 VM 字节码塞进 `.protect` 节、用一堆 SVC trap 做反调，那个才是硬骨头。

---

## 二、先看看壳长什么样

### 2.1 ELF 布局

用 `readelf` 看一眼，这 ELF 结构挺"干净"的：

```
段           虚拟地址             权限    内容
---          ----------           ----    -------------------------
LOAD #1      0x0       - 0xeb458  RW      压缩后的 payload 位流
LOAD #2      0xf0000   - 0x12c481 R+X     解压桩 (stub)
```

ELF 标自己是 DYN（PIE 共享对象），入口地址 `e_entry = 0x12B95C`，落在 LOAD #2 的末尾那几百字节。从外面看就是个普通 ELF，没有 UPX 那种明显的壳特征字符串，挺低调的。

### 2.2 桩里就那么几个函数

整个 RX 段 IDA 只认出 5 个函数，加起来不到 600 字节：

| 函数 | 干了什么 |
|---|---|
| `0x12B95C` `start`（ELF入口） | 位流解压引擎，aPLib / NRV 风格的 LZ77 解码器 |
| `0x12BA0C` | 1-bit 位流读取器——一个同名复用的精巧小函数 |
| `0x12BBBC` | `mmap` 系统调用包装（`SVC 0, w8=222`） |
| `0x12BBD0` | 小型加载器：mmap → 调解码器 → mprotect → BR 跳到真实入口 |
| `0x12BC60` | NULL 终止指针数组扫描，用来跨过 `argv[]` / `envp[]` |
| `0x12BC6C`（子例程） | 真正的 bootstrap：解析 auxv → openat 自己 → 调度 mmap |

### 2.3 字符串特征

唯一的明显标识在 `0x12bb00`：

```
roteVirbox Protector
```

开头被截了一截，完整应该是 "Powered by Virbox Protector" 之类的。其他可见字符串像 `/proc/self/exe`、`/system/bin/linker64`、`Android`、`r17`（NDK r17 编译的痕迹）都是壳运行时要用的常量，跟业务逻辑没任何关系。

---

## 三、壳是怎么跑起来的——运行流程还原

把桩反汇编走一遍，整个运行时间线可以还原成 7 步：

```text
[1] ELF entry 0x12B95C
        ↓
    LDR W19, =0x22                  ; 保存"压缩长度"常量
    BL  0x12BC6C                    ; LR = 0x12B964（后面解码器入口）
        ↓
[2] 0x12BC6C  bootstrap
    MOV  X24, X30                   ; X24 = 解码器入口 0x12B964（后面 BLR X24 用）
    MOV  X0, SP
    BL  sub_12BC60                  ; 跳过 argv[] → X0 = &envp[0]
    BL  sub_12BC60                  ; 跳过 envp[] → X0 = &auxv[0]
        ↓
[3] auxv 扫描
    LDP  X1, X2, [X0],#0x10
    CMP  W1, #6                     ; AT_PAGESZ
    B.EQ ...                        ; 取出 page size → X26 = -pagesize
        ↓
[4] openat(AT_FDCWD, "/proc/self/exe", O_RDONLY)
    SYS_openat = 56                 ; fd 存进 W27
        ↓
[5] sub_12BBD0:
    A) mmap(NULL, size, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0)
       → 拿一块 RW 缓冲（本例 0x1000 字节）
    B) BLR X24                       ; ← 跳进 0x12B964 处的解码器
       解码器把 LOAD#1 段里的位流解到刚 mmap 出来的缓冲
    C) mprotect(buf, len, PROT_R|PROT_X)
       (SYS_mprotect = 226, prot = 5)
        ↓
[6] DC CVAU / IC IVAU / DSB ISH / ISB
    ; ARM64 必备的 D-cache → I-cache 一致性同步
    ; 不刷的话 CPU 可能还在执行旧的指令
        ↓
[7] BR X0
    ; ← 跳到刚解出来的代码入口，正式离开壳的代码
```

第 [7] 步就是经典的"OEP 跳转"（Original Entry Point）。从这一刻起，程序活在 mmap 出来的那块 RWX 内存里，跟磁盘上的 ELF 文件彻底说拜拜。

### 3.1 解码器核心——一个精巧的 6 条指令的位流读取器

`0x12BA0C` 是整个解码器的心脏，只有 6 条指令：

```asm
sub_12BA0C:
    ADDS W4, W4, W4         ; 把 32-bit 位累加器左移，最高位输出到 CF
    CBZ  W4, refill         ; 累加器空了则去补
    RET                     ; CF = 这次读出的 bit
refill:
    LDR  W4, [X0],#4        ; 从输入流再吃 32 bit
    ADCS W4, W4, W4         ; 顺便把第一个 bit 拿出来
    RET
```

这 6 条指令实现了一个"按位读取"的小循环，通过进位标志 CF 返回每次读出的那个 bit。`start` 函数的主循环里反复调它：
- 读一个 bit 决定：是输出字面量，还是做回向复制
- 字面量分支：`LDRB W3,[X0],#1 ; STRB W3,[X2],#1`（直接拷字节）
- 复制分支：用 `ADC W1, W1, W1` 反复积累位，做 Elias-Gamma 编码的长度解析
- 偏移 ≥ 0x500 时自动 `length += 1`（`CMN W5, #0x500 ; CINC W1, W1, CC`）——这是 aPLib 的标志性优化

这些特征跟 **aPLib / NRV2** 系列压缩器完全一致。Virbox 在 ARM64 上选了这族算法做运行时解码引擎，好处是桩可以做到极小（不到 300 字节），解压还极快。

### 3.2 它是双层的

一次脱壳还不够。这个样本是**双层结构**：

```text
壳第 1 层（在磁盘 ELF 里）:
   mmap → 解出 0xa68 字节的 "用户态 ELF loader" → mprotect R+X → BR 进入

壳第 2 层（Layer 1 自己）:
   一个完整的 mini-dl_loader:
   - 复用同一个 0x12B95C 解码器（再次 BL 进去）
   - 把另一段位流解到新 mmap 的 0xd3000 字节区
   - 自己解析 ELF program headers
   - 对每个 PT_LOAD 做 mmap + mprotect
   - 最后跳到内部 ELF 的 e_entry
```

第二层解出来的**才是真正的业务程序**——一个标准 Android `e_type=DYN` 共享对象，`INTERP=/system/bin/linker64`，链接 `libc/libdl/liblog/libz/libm`，有完整的 dynamic symbol 表。

### 3.3 一个小迷惑技巧：伪 ELF 魔数

解出来的 inner ELF，第 4 个字节被动了手脚：

```
正常 ELF:    7F 45 4C 46 02 01 01 00 ...
本样本解出:  0A 00 67 46 02 01 01 00 ...   ← 前 4 字节是垃圾
```

后面 60 字节是完全合法的 ELF header。这是 Virbox 用来对抗"内存扫描 `7F 45 4C 46` 找脱壳产物"的小招数——真实的 magic 由壳在 `BR X0` 之前的某条指令动态修复，静态 dump 的时候如果不知道这一点，会以为这块内存"不是 ELF"，从而错过。

破解方法简单粗暴：**把前 4 字节强制改回 `7F 45 4C 46`**，文件就完整可识别了。

---

## 四、写脱壳脚本——基于 Unicorn 的模拟执行方案

### 4.1 为什么选 Unicorn

先盘一下几种常见的脱壳路子：

| 方案 | 优点 | 缺点 |
|---|---|---|
| 真机 + Frida hook `mprotect` | 真实环境 | 要 root，可能被反 Frida 检测 |
| `gdb` + `dlopen` 调试 | 经典 | 桩里如果有 `ptrace(PTRACE_TRACEME)` 就死 |
| 内存搜索 dump | 简单 | 不知道什么时候该 dump，还要绕 SELinux |
| **Unicorn 模拟** | **沙箱、可控、无需设备** | 要自己实现 syscall 桩 |

这个样本的桩里只有 3 个真正的 syscall —— `openat` / `mmap` / `mprotect`，其余指令全是纯计算 + 位流 + 内存拷贝。把这 3 个 syscall hook 掉，壳的所有"对外接触"就被完全控制了。Unicorn 方案简直是为这种情况量身定做的。

### 4.2 脚本开发的完整思路

#### Step 1 —— 按 program header 加载 ELF

别把整个文件平铺到 base 0，那样 entry `0x12B95C` 处会读到垃圾。必须按 PT_LOAD 的 `vaddr / offset / filesz` 把两段精确映射到 Unicorn 的虚拟地址空间：

```python
for vaddr, off, filesz, memsz, flags in loads:
    uc.mem_map(vaddr & ~0xfff, align_up(memsz), UC_PROT_ALL)
    uc.mem_write(vaddr, elf_raw[off:off+filesz])
```

#### Step 2 —— 伪造启动栈

桩第一件事就是从 SP 读栈，扫 `argv → envp → auxv`，所以必须给它搭一个标准的 Linux entry 栈：

```python
push_words([
    1,                       # argc
    ARGV0_ADDR, 0,           # argv[0], argv NULL
    0,                       # envp NULL
    6, 0x1000,               # AT_PAGESZ
    25, ARGV0_ADDR,          # AT_RANDOM
    31, ARGV0_ADDR,          # AT_EXECFN
    0, 0,                    # AT_NULL
])
```

不搭也能凑合（壳里有 `0x10000` 的 fallback），但**至少要保证 argv/envp 各以一个 NULL 终止**，不然 `sub_12BC60` 会扫越界跑飞。

#### Step 3 —— 从 ELF entry 开跑，别从 bootstrap 开跑

这是一个**很容易踩的坑**。如果直接从 `0x12BC6C` 开始模拟，`X24/X30` 都是 0，后面 `BLR X24` 会跳到 0 崩溃。正确做法：

```python
uc.emu_start(0x12B95C, 0)    # 真·入口
```

因为 `start` 第一条 `BL 0x12BC6C` 会把 `LR=0x12B964` 设好，bootstrap 才能 `MOV X24, X30` 拿到正确的解码器回调地址。这个依赖链我当时踩坑了才想明白。

#### Step 4 —— Hook 三大 syscall，mprotect 是关键

```python
def svc_handler(uc):
    x8 = uc.reg_read(UC_ARM64_REG_X8)
    if x8 == 56:    # openat("/proc/self/exe")
        # 返回一个我们控制的假 fd
        uc.reg_write(UC_ARM64_REG_X0, fake_fd)
    elif x8 == 222: # mmap
        # 在 0x10_0000_0000 之上自增分配
        a = alloc(length)
        uc.mem_map(a, length, UC_PROT_ALL)
        uc.reg_write(UC_ARM64_REG_X0, a)
    elif x8 == 226: # mprotect  ← ★ 关键！
        # 一旦有人把内存改成可执行，立刻 dump！
        addr, length, prot = ...
        if prot & PROT_EXEC:
            data = bytes(uc.mem_read(addr, length))
            with open(f"exec_{addr:010x}_sz{length:x}.bin", "wb") as f:
                f.write(data)
        uc.reg_write(UC_ARM64_REG_X0, 0)
```

这里的核心逻辑是：**`mprotect → R+X` 就是脱壳点的金标准信号**。任何加密 / 压缩 / VM-loader，只要把内存改成可执行，就意味着"我接下来要在这块内存里跑代码了"——这时候 dump 一定能拿到原始机器码。这个信号是 ABI 级别绕不开的，不是这个壳特有的弱点。

#### Step 5 —— 让 Layer 1 也跑完，需要更多 syscall 桩

第一次 `mprotect` 只解出来 4 KB 的 Layer 1 loader。**别急着停**，继续模拟：

- Layer 1 会再次 mmap / mprotect 一块约 836 KB 的内存 → 这才是真正的 payload
- 它需要 `readlinkat("/proc/self/exe")` / `getrandom` / `brk` 等更多 syscall，**全部实现 stub**
- 最终它会 `openat("/system/bin/linker64")` 找不到链接器，自己 `exit_group(127)` 退出——此时 payload 已经完整就位

额外需要实现的 syscall 桩：

```python
SYSCALL_STUBS = {
    62:  "lseek",     63: "read",      64: "write",
    78:  "readlinkat",
    93:  "exit",      94: "exit_group",
    160: "uname",     167: "prctl",
    173: "getrandom", 214: "brk",      215: "munmap",
}
```

每个都要返回合理的成功值，不然壳跑到一半会出错退掉。比如 `readlinkat` 要返回 `"./vmp.sh"` 的链接内容，`getrandom` 就填伪随机字节，`uname` 返回一个假的 `aarch64` 系统信息。意思到了就行，壳不会较真。

#### Step 6 —— 修复伪 ELF 魔数

dump 出来的文件前 4 字节是 `0A 00 67 46`，改回去：

```python
data = bytearray(open('exec_1000011000_szd3000.bin', 'rb').read())
data[:4] = b'\x7fELF'             # 把 0A 00 67 46 改回 7F 45 4C 46
open('unpacked.elf', 'wb').write(bytes(data))
```

修好后 `readelf -l unpacked.elf` 就能看到完整的 9 个 program header，`file` 也会正确识别成 AArch64 共享对象。

#### Step 7 —— 扔进 IDA 分析

把修好的 `unpacked.elf` 拖进 IDA / Ghidra，从 `e_entry=0xFD7C` 开始读。`__libc_init` 之后的 `main` 里就是真正的业务逻辑了。到这一步，加壳保护已经被完全剥掉，剩下的就是正常的逆向分析工作。

> 一个小缺憾：LOAD #2 的数据段（`.data` / `.got` 等，vaddr `0xe3a68` 长 `0x79f0`）在退出时还没被填充（动态链接器没跑，relocations 没做），所以 dump 出来是全 0。对静态分析影响不大——重要的指针都在重定位表里，IDA 会自动解析。

---

## 五、为什么 Unicorn 能秒杀这种壳

回顾一下壳的设计假设和 Unicorn 破解时的现实之间的差距：

| 壳的设计假设 | Unicorn 破解时的现实 |
|---|---|
| "通过 `ptrace(PTRACE_TRACEME)` 抢占调试器" | 我根本不是调试器，我是 CPU 模拟器，壳无法察觉 |
| "通过读 `/proc/self/status` 看 `TracerPid != 0`" | 我可以让 `openat /proc/self/status` 返回任意我想要的字符串 |
| "Cache 一致性指令在用户态会触发 SIGILL" | Unicorn 把 `DC CVAU` / `IC IVAU` 当 NOP 直接跑过去 |
| "`mprotect` 是必须的系统调用，绕不开" | **正因为绕不开，它就是脱壳的"红外感应"，我蹲在那儿就行** |
| "ELF 文件被压缩，静态分析看不到任何业务代码" | 让壳自己解给我看，我只负责 dump |

一句话总结：

> **任何想在用户态执行解压后代码的壳，都必然会调用 `mprotect(_, _, PROT_EXEC)`。这是 ABI 级的约束，只要钩住它，就能拿到任意 packer 的脱壳产物。**

对这个样本而言，**整个脱壳没有用到任何"破解"——它只是模拟硬件，让壳自己把代码摆好给我们看**。

---

## 六、脚本跑起来的效果

完整脚本大概 370 行 Python（主要都在 syscall 桩的处理上）。在 PC 上跑一次几秒钟，产出物：

```
unpacked/xxx_unpacked.elf          ← 864 KB，可直接 IDA 加载
unpacked/exec_1000000000_sza68.bin ← Layer 1 loader（调试参考）
unpacked/exec_1000011000_szd3000.bin ← Layer 2 原始 dump（未修魔数）
unpacked/final_*.bin               ← 退出时所有 mmap 区快照
```

---

## 七、如果碰到 Virbox 的重度配置怎么办

这次的样本只用了轻量模式。生产环境里 Virbox 还可以叠加更多保护，届时 Unicorn 方案需要相应补丁：

| 增强保护 | 现象 | 对策 |
|---|---|---|
| **反调试 syscall** | 桩里调用 `ptrace(PTRACE_TRACEME)`、读 `/proc/self/status` | 在 syscall hook 里假装"我们不是被 trace 的" |
| **TSC / 时间检测** | 反复 `clock_gettime` 看间隔异常长 → 判定被模拟 | 在 hook 里返回线性增长且增量真实的时间戳 |
| **CRC self-check** | 桩跳到 OEP 前先 hash 自身代码段 | 不动桩，只在外面观察，本来就不会触发 |
| **VM 字节码** | OEP 后第一条指令就是 `BR Xn` 进入 VM dispatcher | **Unicorn 救不了你**，需要重建 VM handler 表 → 翻译回原生 ARM64 |
| **TLS callback** | 在 `__libc_init` 之前的 `.init_array` 里偷偷再解一层 | 把模拟跑到 `main` 之前更晚的位置再 dump |
| **SIGTRAP 自捕获** | 故意触发 BRK，在自己注册的 signal handler 里做关键判断 | 在 Unicorn 里实现 `kill -SIGTRAP` 的等价模拟，接管 sigaction |

最难啃的是**代码虚拟化**——一旦关键函数被翻译成 VM 字节码，静态 dump 出来的只是一堆 dispatcher 循环，**没有 ARM64 业务指令可读**。脱壳只能解决"壳"的部分，VM 还得另外做 devirtualization，那是另一个故事了。

---

## 八、小结

回到这次实践，几个关键点：

1. **壳的本质就是把原始 ELF 用 aPLib 风格 LZ 压成位流，运行时 mmap → 解压 → mprotect → BR 跳入**，理解了这个模式，脱壳思路就有了
2. **双层结构比较常见**——第一次解出来的是 loader，第二次才是真身
3. **`mprotect(R+X)` 是脱壳的万能信号**——hook 住它，蹲点 dump
4. **Unicorn 模拟执行是处理纯自解压壳的最干净手段**——不是破解，只是让壳帮我跑了它本该跑的流程
5. 脱完别忘了检查魔数——作者可能会耍些小花样，比如把 `ELF` 魔数改掉
6. 碰上开启了 VM 虚拟化的重度壳，Unicorn 只能帮你脱到 VM 那层，反虚拟化是另一个维度的战斗

整个过程说到底就一句话：**壳想藏代码，但它总得在某个时刻把代码解出来跑，那个时刻就是你的机会。**
