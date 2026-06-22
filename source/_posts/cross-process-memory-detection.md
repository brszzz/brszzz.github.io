---
title: 跨进程内存读写的攻防博弈——从内核缺页陷阱到应用层数据溯源
date: 2026-06-04 17:01:00
tags:
  - Android
  - ARM64
  - 跨进程
  - 内存检测
  - Linux内核
  - PMU
  - 蜜罐
  - 游戏安全
categories:
  - 安全分析
description: ARM64 Android 平台 process_vm_readv/writev 检测方法的完整探索，实测 mincore 自检、PerfEvent 跨通道测序、PMU 硬件计数器等十余种方案，分析 root 权限攻击者的规避手段与残留检测信号。
---

# 跨进程内存读写的攻防博弈：从内核缺页陷阱到应用层数据溯源

> ARM64 Android 平台 `process_vm_readv` / `process_vm_writev` 检测方法的完整探索、实验验证与攻防进化

## 摘要

本文系统研究 Android ARM64 平台上跨进程内存读写的可检测性。通过构建检测框架（detector）与攻击工具（attacker），在 Linux 5.4.210 内核上实测了 mincore 自检、PerfEvent 跨通道测序、内存访问时延、ARMv8 PMU 硬件计数器、kprobes 内核挂钩、应用层蜜罐令牌等十余种检测方法。核心发现：MADV_DONTNEED 陷阱页 + mincore 自检构成最强用户态检测信号；perf_event 与 /proc/self/stat 在 FOLL_REMOTE 缺页会计上的不一致形成高信噪比侧信道；但 root 权限的攻击者通过逐页 /proc/pid/pagemap 探测可将内存层副作用压缩至 0.13% 误读率（31/23936），D5 DTLB +101%、D6 RefLat -33% 等 PMU 级残留信号仍不可消除；用户态攻防的最终防线转移至应用层数据使用检测。本文还探索了 ARMv8 PMU 硬件计数器、LLCC-PMU、REMOTE_ACCESS 等五个硬件方向的可行性，均因 task-context 隔离或 SELinux 限制而失败。

---

## 1. 项目概述

本项目实现了一套 Android ARM64 平台上对 `process_vm_readv` / `process_vm_writev` 跨进程内存读写的检测框架，包含：

- **detector**：检测守护进程，监控自身内存是否被外部进程读写
- **attacker**：攻击模拟工具，使用 `process_vm_readv/writev` 读写目标进程内存

### 权限模型

本文中攻击者始终为 **root 权限**，防御者为 **非 root 用户权限**。攻击者通过 `/proc/<pid>/pagemap` 实现跨进程内存布局探测。`mincore()` 只能检查调用者自身地址空间的 PTE，无法跨进程使用——防御者用它自检是合法的，攻击者的跨进程探测手段始终是 pagemap（需 root）。

---

## 2. 检测方法总览

| 方法 | 原理 | 检测读 | 检测写 | 本设备实测 |
|------|------|:---:|:---:|------|
| **mincore** | MADV_DONTNEED 回收页面后检查是否变 resident | ✅ | ❌ | ✅ 有效 |
| **Canary** | 内存末尾嵌入校验值，比对是否被篡改 | ❌ | ✅ | ✅ 有效 |
| **Swap** | MADV_PAGEOUT 换出后检查 VmSwap 是否下降 | ❌ | ❌ | ❌ process_vm_readv 不走 swap-in |
| **Referenced** | /proc/smaps Referenced 位检查 | ❌ | ❌ | ❌ FOLL_REMOTE 不置 Accessed |
| **CacheFlush** | dc civac 刷缓存后测访问延迟 | ❌ | ❌ | ❌ 该设备内核拦截用户态 dc civac |
| **GuardPage** | PROT_NONE 守卫页包围数据区 | ❌ | ✅ | 仅写检测有效 |

---

## 3. mincore/pagemap 绕过分析

### 3.1 关键前提：mincore() 不能跨进程探测

`mincore()` 只能检查**调用者自身**地址空间的 PTE。外部攻击者无法用 `mincore()` 探测目标进程的内存驻留状态。跨进程驻留探测的唯一用户态手段是 `/proc/<pid>/pagemap`（需 root 权限或相同 UID）。

### 3.2 原始绕过（独立 mincore_region）

攻击者通过 `/proc/<pid>/pagemap` 探测目标进程内存布局（bit 63 = page present）：发现连续 2MB evicted 区域 → 这是独立的 `mincore_region` → 直接跳过；读其他 resident 页面 → 不触发任何检测。

### 3.3 修复1：陷阱页散布

取消独立 `mincore_region`，改为在 `ref_region`（2MB 数据区）内散布 64 个陷阱页。

**攻击者 pagemap 视角**：

```
X..............X......X......X......X......X......X......X......
```

（X = 陷阱/evicted，. = 数据/resident）

攻击者需逐页探测 512 次才能避开所有陷阱。**限制**：陷阱位置静态，攻击者探测一次即可永久避开。

### 3.4 修复2：陷阱轮换

每轮扫描后：
1. 恢复旧陷阱页（写入数据使其变 resident）
2. 用 `cntvct_el0 ^ round` 做种子重新随机选取陷阱
3. 回收新陷阱页

```c
uint64_t tsc;
__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(tsc));
int seed = (int)((tsc ^ (tsc >> 12) ^ (ctx->round * 0x9E3779B9)) & 0xFFFF);
```

**效果**：陷阱位置每轮变化，攻击者探测立即过时。

### 3.5 残留绕过

pagemap 读取极快（pread 单次 8 字节、无需遍历页表），攻击者可在轮换间隔内完成：读 `/proc/<pid>/pagemap` → 获知当前陷阱分布 → 读安全页 → 在下一轮轮换前完成。

**根本原因**：pagemap 只读页表查询，不修改 PTE、不触发缺页、不改变任何被监控页状态。

---

## 4. MinFlt 检测

### 4.1 原理

`process_vm_readv` 内核路径：

```
process_vm_readv → pin_user_pages_remote → __get_user_pages → faultin_page
→ handle_mm_fault → 目标进程 min_flt++
```

读已回收（MADV_DONTNEED）页面会触发目标进程 minor page fault。监控 `/proc/self/stat` 的 `min_flt` 字段可检测。

### 4.2 实测基线

无攻击时每轮 `min_flt +64~67 (self:~74)`。detector 自身活动产生 64-67 faults/round。噪声 ~±7。外部需读 >7 页才超噪底。

### 4.3 局限

- 信噪比低：少量读取 (< 7 页) 时信号淹没在噪声中
- 读 resident 页不产生 fault，不触发
- pagemap 预探测 + 仅读 resident 页可绕过
- 与 mincore 互补：mincore 检读陷阱页，MinFlt 检大规模读取

---

## 5. perf_event tracepoint 尝试

### 5.1 方案

用 `perf_event_open(PERF_TYPE_TRACEPOINT, raw_syscalls/sys_enter)` 全局捕获 syscall：

```
raw_syscalls/sys_enter → 过滤 id==270 (process_vm_readv) + args[0]==本进程PID → 检测
```

### 5.2 实测结果

- `perf_event_open` 成功，ring buffer 收到事件
- 但所有事件的 `id` 字段恒为 98 (futex)，从未出现 270
- ftrace 直接验证：`echo 1 > raw_syscalls/enable` → `entries-written: 0`
- **根因**：该 Android 内核 (5.4.210) 的 `raw_syscalls` tracepoint 不生成事件（`CONFIG_FTRACE_SYSCALLS` 未完整配置）

### 5.3 结论

perf_event tracepoint 方案在具备完整 syscall tracepoint 支持的内核上可用，但本设备不支持。代码已移除。

---

## 6. kprobes 检测方案

### 6.1 原理

不依赖 tracepoint，直接用 kprobe 钩在内核函数入口：

```
__arm64_sys_process_vm_readv → process_vm_rw_core(pid, ...)
```

`process_vm_rw_core` 第一个参数就是目标进程 PID，kprobe 捕获 `%x0` 即可。

### 6.2 设置

```bash
echo 'p:vmrw process_vm_rw_core pid=%x0' > /sys/kernel/tracing/kprobe_events
echo 1 > /sys/kernel/tracing/events/kprobes/vmrw/enable
```

### 6.3 实测输出

```
attacker-30442 → vmrw: process_vm_rw_core  pid=0x76df (=30431, detector PID)
attacker-30445 → vmww: __arm64_sys_process_vm_writev  (writev 也捕获)
```

**精确捕获到 attacker 对 detector 的 process_vm_readv 和 process_vm_writev 调用。**

### 6.4 kprobe vs mincore 对比

| | kprobes | mincore |
|------|---------|---------|
| 检测原理 | 直接钩 syscall 入口 | 检测页面常驻变化 |
| 能否被 pagemap 绕过 | ❌ 不可绕过 | ✅ 可绕过 |
| 是否误报 | 否 | 是（CacheFlush 始终误报） |
| 需要 root | ✅ | ❌ |
| 检测 writev | ✅ | ❌ |

---

## 7. perf_event 侧信道测序

### 7.1 核心发现

perf_event 和 /proc/self/stat 对 `process_vm_readv` 触发的 minor page fault **不一致**：

| 测量通道 | process_vm_readv 后 | 原因 |
|---------|-------------------|------|
| `/proc/self/stat` min_flt | **有增量** (+N faults) | `mm_account_fault` 通过 `FOLL_REMOTE` 路径累加到目标 mm 关联的 task |
| `perf_event(PERF_COUNT_SW_PAGE_FAULTS_MIN)` | **无增量** | `perf_sw_event()` 在 attacker 的 task context 触发，不递送到目标进程 perf counter |

### 7.2 跨通道检测原理

利用两个通道的差异构成侧信道：

```
external_faults = delta_min_flt - delta_perf_faults
if external_faults > 0 → process_vm_readv 检测到!
```

- `perf_event` 计数**仅自身 task context** 内的 fault（外部攻击不影响）
- `/proc/self/stat` 计数**全部** fault（包括外部 `FOLL_REMOTE` 触发的）
- 差值自动抵消自身活动，无需精确校准 `expected_self_faults`

### 7.3 实测结果

**无攻击基线**（每轮 ~3-4ms task_clock，两侧完全同步）：

```
Round 2   stat:+64  perf:+64  ext:+0   clock:3929us
Round 3   stat:+64  perf:+64  ext:+0   clock:3605us
...
```

**攻击** — attacker 对 ref_region 执行 200 页 process_vm_readv，命中 25/64 trap pages：

```
--- Detector Round 8 ---
mincore        | YES        | 25/64 trap pages resident
MinFlt         | YES        | min_flt spike +89 (self ~74, excess 15)
PerfEvent      | YES        | stat:+89 perf:+64 ext:+25 clock:4101us
-----------------------------------------------------------------
[!!!] 3 non-cache method(s) detected attack!
```

**关键对比**：

| 回合 | stat (含外部) | perf (自身) | ext (外部fault) | 判定 |
|------|:---:|:---:|:---:|------|
| 基线 R2-R7 | +64 | +64 | **0** | 正常 |
| 攻击 R8 | **+89** | +64 | **+25** | ✅ 检测 |

ext:+25 精确等于 mincore 的 25/64 trap pages resident，证明每个外部 fault 都对应一个被 `process_vm_readv` 读回的陷阱页。

### 7.4 对比 MinFlt

| | MinFlt (/proc/self/stat) | PerfEvent 跨通道 |
|---|---|---|
| 检测原理 | 单通道绝对值 vs 预期校准值 | 双通道差值 |
| 需要校准 | ✅ 需要 `expected_self_faults` | ❌ 自动抵消自身活动 |
| 信噪比 | 低（excess=2 时接近噪底） | 高（ext=+25 时信号清晰） |
| 误报风险 | 自身活动波动导致误报 | 低（两边同时增加，差值不变） |

### 7.5 绕过分析

**pagemap 探测是否可检测？** 实测：attacker 仅调用 pagemap probe，不执行 readv → 12 轮全部 ext:+0。**pagemap 探测不可检测**。`pagemap_read()` 只读内核页表（`mmap_read_lock` + PTE 遍历），不修改 PTE、不触发 fault、不在目标 task context 产生 perf event。

**pagemap + 仅读 resident 页能否绕过？** 实测：448/512 页 (87.5%) 为 resident 数据页，可被安全读取。完整绕过链：

```
1. pagemap probe  →  获知 X (evicted/trap) vs . (resident/data)
2. process_vm_readv 仅读 . (resident) 页  →  0 次 fault
3. detector: ext = 0, mincore 0 trap resident  →  无报警
```

**绕过的对抗——trap 轮换**：攻击者必须 pagemap 探测后、下一轮轮换前完成读取。一旦轮换触发，旧 trap 恢复、新 trap 回收，pagemap 探测结果立即过时。缩短 detector 扫描间隔可压缩攻击窗口。

---

## 8. ARM64 硬件 PMU 检测方案研究

### 8.1 测试环境

| 项目 | 值 |
|------|-----|
| SoC | Qualcomm (Cortex-A55 x4 + Cortex-A75 x2+) |
| PMU | ARMv8 PMUv3 |
| 内核 | 5.4.210-qgki |
| perf_event_paranoid | -1 |
| UID | 2000 (shell) |
| SELinux | Enforcing |

### 8.2 五个探索方向

#### 方向 1：系统级监控 (pid=-1, cpu=N)

绕过 task-context 隔离的最直接方法——监控整个 CPU 而非特定进程。所有 CPU (0-7)、所有 event type 均返回 EACCES。**SELinux 阻止了 shell 用户进行系统级 PMU 监控**，即使 paranoia=-1。

#### 方向 2：Qualcomm LLCC-PMU（系统级 Cache Controller）

LLCC (Last Level Cache Controller) PMU 是系统级 uncore PMU，理论上可观测所有处理器的缓存流量。设备节点存在 (`/sys/devices/platform/soc/9095000.llcc-pmu`)，模块已加载 (`llcc_perfmon`)，但 sysfs type 文件不可读（SELinux），events 目录不存在，pid=-1 打开全部 EACCES。**硬件存在但用户态完全无法访问**。

#### 方向 3：ARMv8 RAW Event 编码探索

无法读取 `/sys/bus/.../format/event` 文件（SELinux），只能盲测 raw event 编码。

| 事件码 | 名称 | 自访问计数 | 备注 |
|--------|------|-----------|------|
| 0x11 | CPU_CYCLES | 376K delta | 正常工作 |
| 0x3100 | REMOTE_ACCESS? | 微弱 (172) | 仅 busy-loop 自身产生 |
| 0x03 | L1D_CACHE_REFILL | 始终 0 | 编码不匹配或未实现 |
| 0x17 | L2D_CACHE_REFILL | 延迟激活 | multiplexing 调度到时才有值 |

**REMOTE_ACCESS (0x31) 深入测试**：ARMv8 事件 0x31 定义"来自其他处理器的访问"——检测跨进程内存访问最理想的 PMU 事件。config=0x0031 和 config=0x3100 均无信号，**受控实验中攻击阶段与控制组无差异**。

#### 方向 4：PERF_TYPE_HW_CACHE 测试

- L1D_READ_ACCESS: 工作 (111K delta, 自访问)
- L1D_READ_MISS: 工作 (3K delta, 自访问)
- LL_READ_ACCESS: **ENOENT**（该硬件不支持 LL cache 事件）
- LL_READ_MISS: **ENOENT**
- DTLB_READ_ACCESS/DTLB_READ_MISS: 工作

LL（Last Level）cache 事件不可用，无法通过通用接口监控 L3 缓存。

#### 方向 5：未知 PMU Type 8 & 10

| Type | pid=0 行为 | pid=-1 行为 | 推测 |
|------|-----------|-----------|------|
| 8 | 多种 event 产生有效计数 | EACCES | CPU PMU 别名或 DSU PMU |
| 10 | 所有 event delta=0 | EACCES | 可能是未初始化的 llcc-pmu |

### 8.3 严格受控实验：跨进程攻击 PMU 信号

**实验设计**：父进程 busy-loop 维持 CPU 上下文 + 四阶段对照（IDLE/CTRL/ATTACK/VERIFY）。

**实测结果**（所有 HW/RAW 计数器）：

| Counter | IDLE | CTRL | ATTACK | VERIFY | 判定 |
|---------|------|------|--------|--------|------|
| HW_CACHE_MISS | 0-428 | 0-301 | 0 | 0-679 | 无差异 |
| HW_BUS_CYCLES | 0-516K | 0-1.4M | 0-1.37M | 0-708K | 无差异 |
| REMOTE_0x3100 | 0 | 0 | 0 | 0 | 无信号 |
| BUS_0x1900 | 0 | 0 | 0 | 0 | 无信号 |
| SW_FAULTS | 0 | 0 | 0 | 0 | 无信号 |

**结论：所有 HW/RAW 计数器在攻击阶段与控制组无显著差异。** 父进程 PMU 只反映自身 busy-loop 活动量，不反映子进程跨进程内存访问。

### 8.4 根因分析

ARM64 PMU task-context 隔离机制，三个潜在绕过路径均被阻塞：

| 绕过路径 | 状态 | 阻塞原因 |
|---------|:---:|------|
| 系统级监控 (pid=-1) | FAIL | SELinux EACCES |
| llcc-pmu (uncore) | FAIL | sysfs 不可读 + pid=-1 EACCES |
| REMOTE_ACCESS event (0x31) | FAIL | 仍受 task-context 限制 |
| 缓存一致性流量 (HW_BUS_CYCLES) | FAIL | 仅计数本 task 调度时段 |

### 8.5 PMU 研究最终结论

**ARM64 硬件 PMU 在用户态下无法检测 process_vm_readv。** 这不是权限问题（paranoia=-1 名义上允许所有事件），也不是编码错误（通过各种编码尝试和对照实验排除），而是 ARM PMU 架构的根本设计——task-context 隔离使目标进程的 PMU 无法感知其他进程的微架构事件。系统级 PMU（uncore/DSU/LLCC）理论上可绕过隔离，但 SELinux 阻止了用户态访问。用户态下唯一有效方案是已验证的 **PerfEvent 跨通道测序**。

---

## 9. 内存访问时延检测

### 9.1 原理

不依赖 perf_event 或 mincore，纯用户态计时区分驻留页与非驻留页：

```
非驻留页: MADV_DONTNEED 回收 → 访问触发缺页 → ~2000-5000ns
驻留页:   已在物理内存中 → 访问走缓存 → ~50-150ns
差异: ~20-50x，clock_gettime 分辨率 (~50ns) 足以分辨
```

### 9.2 校准数据

| 访问类型 | 时延 | 说明 |
|---------|------|------|
| 驻留页（缓存命中） | p50=52ns, p99=105ns | 直接 L1 缓存访问 |
| 非驻留页（缺页） | min=1823ns, median=1927ns | 内核缺页处理 |
| clock_gettime 开销 | 52-104ns | 测量噪声 |
| 检测阈值 | 5x resident p99 = 525ns | 动态校准 |

### 9.3 检测流程

```
madvise(DONTNEED) → 所有陷阱页非驻留
       ↓
  等待窗口 (200ms) ← attacker 的 process_vm_readv 触发 FOLL_REMOTE 缺页
       ↓
  定时探测: clock_gettime + 读操作计时
       ↓
  dt < 525ns → 页已驻留 → 有外部访问
  dt > 1800ns → 页仍缺页 → 无外部访问
```

### 9.4 实测结果

- **基线（无攻击）**：20 轮 Fast=0，零假阳性
- **攻击检出**：匹配 attacker 读 16 页命中约 4 个 trap（25% 密度）
- **信号对比**：驻留页 156ns vs 缺页 1875ns，12:1 信噪比

### 9.5 优势与局限

**优势**：不需要 CONFIG_PERF_EVENTS，不需要 mincore() 系统调用，纯用户态，attacker 无法感知（无 syscall 痕迹）。

**局限**：与所有 fault 类检测共享同一个根本弱点——依赖非驻留陷阱页。攻击者可通过 `/proc/<pid>/pagemap` 预探测避开。

---

## 10. 陷阱轮换 vs pagemap 预探测——竞态窗口测试

### 10.1 架构说明

以下竞态测试采用独立进程架构：防御者进程（非 root 用户）和攻击者进程（root 权限）完全独立，不共享内存。防御者启动后输出其 PID 和内存地址；攻击者通过命令行参数获取目标信息，使用 `/proc/<pid>/pagemap`（root 权限）做跨进程探测，使用 `process_vm_readv` 做跨进程读取。

### 10.2 测试设计

Defender 每轮轮换陷阱页（MADV_DONTNEED 新集合），Attacker 先 pagemap 预探测再长时间读取。

```
Defender: ─── 陷阱集A ─── 陷阱集B ─── 陷阱集C ───
           | 200ms | 200ms | 200ms |

Attacker:  [pagemap探测]────── 逐页 process_vm_readv ──────]
           |← 竞态窗口 (3-320ms) →|
```

### 10.3 实测结果（独立进程）

测试参数：256 页缓冲区，64 个陷阱页 (25%)，200ms 轮换周期，64 页读取量。

| 页间延迟 | 读取窗口 | vs 200ms轮换 | readv故障 | 检出 |
|:---:|------|:---:|:---:|:---:|
| 0ms | ~3ms | 远小于 | 0 | ❌ 0% |
| 1ms | ~67ms | 小于 | 0 | ❌ 0% |
| 2ms | ~131ms | 临界重叠 | 0 | ❌ 0% |
| 3ms | ~195ms | 接近重叠 | 0 | ⚠️ 20% |
| 5ms | ~323ms | 完全跨越 | 0 | ⚠️ 20% |

**与 fork+MAP_SHARED 模拟的关键差异**：原始 fork 模拟实验报告了 93% 检出率 (5ms 延迟)。独立进程架构下，攻击者的 pagemap 探测直接读取目标进程页表（一次 pread 8 字节），探测速度极快 (~0.7ms 扫描 256 页)，批量 readv 后无回读确认。process_vm_readv 命中已回收页时会触发 FOLL_REMOTE 缺页（目标 min_flt 增加），但 readv 返回成功（内核自动补页），攻击者侧无感知。防御者侧的 min_flt 偶尔能捕获这些外部 fault，但信号不稳定。

---

## 11. 逐页 pagemap——用户态攻防的终点

### 11.1 攻击升级

攻击者将"先探测再批量读"改为"每读一页前都通过 pagemap 检查"：

```
传统方案: pagemap(全部) → readv(p1) → readv(p2) → ... → readv(pN)
                              |← 竞态窗口可达数百ms →|

逐页方案: pagemap(p1)→readv(p1) → pagemap(p2)→readv(p2) → ...
                 |← 17μs →|          |← 17μs →|
```

### 11.2 实测数据

逐页 pagemap + readv，512 页缓冲区（64 traps），200ms 轮换周期：

**攻击者侧 — 逐页 pagemap 判断 + 跳过非驻留页**：

```
Initial probe: 448 resident, 64 evicted (12.5% traps)

逐页结果 (512 页全量):
  pagemap → resident → READ  → OK:   448 页 (87.5%)
  pagemap → evicted  → SKIP → -:     64 页 (12.5%)
  readv 失败:                           0 页 (0%)

  Avg pagemap 耗时: 1871 ns/page
  Avg readv 耗时:   ~3300 ns/page
  陷阱规避率:      100% (64/64 traps correctly skipped)
```

**防御者侧**：

```
Baseline:        64 min_flt/round
trap_resident:    0 (全程)
min_flt delta:   64 (=baseline)
excess:           0
Status:          - (无检出)
```

### 11.3 竞态窗口计算

```
逐页窗口 = pagemap pread(8 bytes) + readv = ~3-6μs
轮换周期 = 200ms = 200,000μs
命中概率 = 4 / 200,000 = 0.002%
→ 约 50,000 次读取才期望命中 1 次陷阱
```

### 11.4 代价对比

| | 批量预探测 | 逐页 pagemap |
|------|:---:|:---:|
| 竞态窗口 | 3-320ms | **3-6μs** |
| 陷阱命中率 | 0-20% | **<0.01%** |
| 内存侧信道可检测 | ⚠️ 偶发 | **❌ 不可检测** |
| syscall 次数 (64页) | 65 | 128 |
| syscall 特征 | 低 | 高（交替 pagemap+readv 模式） |
| 读取吞吐 | 高 | 降低 ~50% |

### 11.5 极限竞态测试

| 轮换速度 | 持续时间 | 攻击读取量 | 跳过率 | readv 失败 | 平均窗口 |
|---------|---------|-----------|------|:---:|------|
| 200ms | 10s | 3.47M | 12.11% | 0 | 2.5μs |
| 50ms | 10s | 3.01M | 12.67% | 0 | 2.9μs |
| 10ms | 10s | 2.97M | 12.98% | 0 | 2.9μs |
| **0ms（忙循环）** | **10s** | **2.15M** | **19.86%** | **0** | **3.9μs** |

**总计 ~11.6M 次 pagemap+readv 操作，0 次 readv 失败。**

### 11.6 pagemap 为什么不可检测

```
pagemap 读取路径 (/proc/<pid>/pagemap):
  pread(fd, &entry, 8, pfn*8)  // 只读 /proc 文件
  → 内核: pagemap_read() → walk_page_range() (只读)
  → 不修改 PTE，不触发缺页，不产生 I/O，不改变任何计数器

mincore() (防御者自检) 同样不可检测:
  down_read(mm->mmap_lock)    // 共享读锁
  walk_page_range()           // 只读遍历页表
  up_read(mm->mmap_lock)

副作用: 无。不产生缺页，不修改 Accessed bit，不触发 I/O，不改变 stat
```

### 11.7 攻防升级链

```
L1  直接 readv           →  PerfEvent跨通道 / 时延检测     ✅ 用户态可检测
L2  pagemap预探测+批量读  →  陷阱轮换 (竞态窗口)           ✅ 用户态可检测
L3  逐页 pagemap+readv   →  内存驻留检测几乎失效           ⚠️ 仅 PMU 级残留
                            syscall 模式监控               🔒 需 root
L4  —                    →  kprobes/eBPF 钩内核            🔒 需 root
```

### 11.8 用户态攻防终止线

逐页 pagemap + process_vm_readv 将可检测的"缺页"替换为几乎不可检测的"页表只读查询"。从受害者视角，`/proc/self/stat` 和 `perf_event` 计数器几乎无变化——但并非绝对零信号：六维度 PMU 实验中 pagemap 模式仍有 31 次误读（0.13%），D5 DTLB Walk +101%、D6 RefLat -33%。**攻击者无法完美隐身，残留信号仅 PMU 级别的统计检测可能捕获。**

---

## 12. 应用层蜜罐——数据溯源检测

### 12.1 核心洞察

**把问题从"检测内存被读"转变为"检测数据被用"。**

```
传统方法 (内核层):  内存访问 → 追踪内核副作用 (缺页/缓存/PMU)
                          ↓ 逐页 pagemap 可消除所有内存副作用
                          ↓ 用户态检测终点

蜜罐方法 (应用层):  内存访问 → 获取数据 → 使用数据 → 产生可观测副作用
                                               ↑
                                          在这里检测!
```

**关键不对称优势**：`pagemap`（攻击者跨进程探测）能区分驻留页 vs 非驻留页（躲避陷阱页），但**不能区分合法数据 vs 蜜罐数据**（两者都是驻留页中的普通字节）。防御者自身的 `mincore()` 同样只能做驻留/非驻留判断，没有语义理解能力。

### 12.2 蜜罐令牌结构

```c
#define HONEYPOT_MAGIC 0x484F4E4559504F54ULL  // "HONEYPOT"

struct HoneypotToken {
    uint64_t magic;       // 蜜罐标识 (固定魔数)
    uint64_t region_id;   // 内存区域标识 (溯源到具体数据区)
    uint64_t token_seq;   // 区域内序号
    uint64_t checksum;    // HMAC-like 校验 = hash(magic|region_id|seq|secret)
};
```

每个会话使用随机 `secret`，攻击者即使知道令牌格式，没有 `secret` 也无法区分真实令牌和随机数据（假阳性不可区分）。

### 12.3 三种蜜罐模式及实测

#### MODE 1：静态令牌嵌入（数据溯源）

```
Defender:  在敏感缓冲区嵌入令牌 (与合法数据交织, 无法从字节区分)
Attacker:  逐页 pagemap + process_vm_readv (root) → 读取全部内存
           → 将数据写入输出信道 (模拟外泄/渲染)
Defender:  扫描输出信道 → 检测令牌签名 → 确认内存被读取
```

**实测结果**（`honeypot_test mode 1`）：

```
Session secret: 0x6a227b5b4f779cf3
[Defender] Embedded 16 tokens in 1048576-byte buffer
[Defender] Read 1048576 bytes from exfiltration channel

*** MEMORY READ DETECTED! ***
16 honeypot tokens found in attacker's output
Data provenance confirmed: region_id=1
```

**16/16 令牌全部检出**。攻击者无法用 pagemap 区分令牌页（全部在驻留页中）。

#### MODE 2：Liveness Check（令牌逃逸检测）

```
Defender:  创建 3 个区域 (region 100/200/300), 各有独立令牌
           定期扫描外部监控信道 (模拟网络流量/日志监控)
Attacker:  L3 攻击 (逐页 pagemap + readv) — 此前认为不可检测
           → 将窃取的数据写入监控 buffer
Defender:  Liveness 扫描 → 检测到令牌 → 确认内存被读
```

**实测结果**（`honeypot_test mode 2`）：

```
Region 100: 16 tokens
Region 200: 16 tokens
Region 300: 16 tokens

Round    Status               Details
0        clean                No tokens detected
1        *** BREACH! ***      Tokens detected in monitor buffer
  → 1 tokens from region(s): 100
  → L3 attack (per-page pagemap) DETECTED via data provenance!
```

**L3 攻击被检测到**。逐页 pagemap 可以在内存层消除所有副作用，但无法阻止数据在使用层被追踪。

#### MODE 3：自反噬陷阱值（使用即触发）

在内存中放置特殊构造的值，攻击者解释并使用时产生可观测副作用。三种自反噬机制：

1. **指针陷阱**：`token = &monitored_page`，攻击者解引用 → 访问被监控页 → 可检测
2. **范围/索引陷阱**：`token = sentinel_array_index`，攻击者用作索引 → 访问哨兵元素 → 可检测
3. **校验和陷阱**：token 嵌入数据结构，攻击者输出中包含 token → 可鉴定来源

### 12.4 蜜罐 vs 陷阱页对比

| 维度 | 陷阱页 (Trap Page) | 蜜罐令牌 (Honeypot Token) |
|------|-------------------|--------------------------|
| **检测层** | 内存管理层（缺页） | 应用数据层（数据使用） |
| **pagemap 能否区分** | ✅ 能（非驻留 vs 驻留） | ❌ 不能（都是普通字节） |
| **竞态窗口问题** | 有（轮换 vs 探测） | 无（令牌始终在内存中） |
| **检测时机** | 访问时（实时） | 使用时（事后/实时） |
| **前提条件** | 攻击者读非驻留页 | 攻击者使用窃取的数据 |
| **绕过方法** | 逐页 pagemap (L3) | 不使用窃取数据（但使用才能获益） |

### 12.5 攻防进化链（扩展）

```
L1: 直接 process_vm_readv
    → 陷阱页检测 (min_flt)                                   ✅ 可检测

L2: pagemap 预探测 + 批量读 resident 页
    → 陷阱轮换制造竞态窗口                                    ✅ 可检测

L3: 逐页 pagemap + process_vm_readv (竞态窗口 ~17μs)
    → 内存副作用检测几乎失效，仅 PMU 级残留 (D5+101%)        ⚠️ 几乎不可检测

L4: L3 + 使用窃取的数据 (渲染/外泄/计算)
    → 应用层蜜罐 (数据溯源)                                  ✅ 可检测 ← 新增!
```

---

## 13. 无需 root 权限的检测方法总结

用户态下（非 root）可用的检测方法及其效果：

| 方法 | 检测 readv | 检测 writev | 绕过难度 | 备注 |
|------|:---:|:---:|------|------|
| **PerfEvent**（跨通道） | ✅ | ❌ | 中等 | stat vs perf 差值；自动抵消噪声；信噪比最高 |
| **时延检测** | ✅ | ❌ | 中等 | 纯用户态计时；无需 perf_event；无需内核配置 |
| **mincore**（陷阱散布+轮换） | ✅ | ❌ | 中等 | 需 pagemap 探测+避开陷阱；轮换提高难度 |
| **MinFlt**（/proc/self/stat） | ✅（大量） | ❌ | 中等 | 少量读 (<7页) 信号淹没在噪声中 |
| **陷阱轮换**（竞态窗口） | ✅ | ❌ | 困难（对批量读） | 逐页 pagemap 可消除竞态窗口 |
| **蜜罐令牌**（数据溯源） | ✅ | ❌ | 极高 (L4) | 检测数据"使用"而非内存访问；pagemap 免疫 |
| **Canary** | ❌ | ✅ | 低 | 唯一检测 writev 的用户态方法 |
| **GuardPage** | ❌ | ✅ | 低 | 检测数据区篡改 |
| Referenced | ❌ | ❌ | — | FOLL_REMOTE 不置 Accessed |
| Swap | ❌ | ❌ | — | 不走 swap-in 路径 |
| /proc/self/io | ❌ | ❌ | — | rchar/read_bytes 不变 |
| 时延检测（无陷阱页） | ❌ | ❌ | — | 缓存一致性效应 <10ns, 淹没在噪声中 |
| PMU HW 计数 | ❌ | ❌ | — | ARM task-context 隔离 |

---

## 14. 全部检测方法对比总表

| 方法 | 检测读 | 检测写 | 需root | 绕过难度 | 本设备可用 | 原理 |
|------|:---:|:---:|:---:|------|:---:|------|
| **kprobes** | ✅ | ✅ | ✅ | 不可绕过 | ✅ | 钩内核函数 process_vm_rw_core |
| **eBPF** | ✅ | ✅ | ✅ | 不可绕过 | 理论可用 | kprobe BPF 程序过滤 |
| **mincore**（陷阱散布+轮换） | ✅ | ❌ | ❌ | 中等 | ✅ | MADV_DONTNEED + mincore 驻留检测 |
| **时延检测**（陷阱页） | ✅ | ❌ | ❌ | 中等 | ✅ | 纯用户态 clock_gettime 计时；无需 perf_event |
| **PerfEvent**（跨通道） | ✅ | ❌ | ❌ | 中等 | ✅ | /proc/stat vs perf_event fault 差值 |
| **MinFlt** | ✅ | ❌ | ❌ | 中等 | ✅ | /proc/self/stat min_flt 增量 |
| **陷阱轮换**（竞态窗口） | ✅ | ❌ | ❌ | 困难（批量读） | ✅ | 缩短轮换周期→压缩安全窗口；逐页pagemap可消除 |
| **蜜罐令牌**（数据溯源） | ✅ | ❌ | ❌ | 极高 (L4) | ✅ | 检测数据使用而非内存访问；pagemap免疫 |
| **Canary** | ❌ | ✅ | ❌ | 低 | ✅ | 内存校验值比对 |
| **GuardPage** | ❌ | ✅ | ❌ | 低 | ✅ | PROT_NONE 守卫页 |
| Referenced | ❌ | ❌ | ❌ | — | ✅ | /proc/smaps Referenced 位 |
| Swap | ❌ | ❌ | ❌ | — | ✅ | VmSwap 变化 |
| CacheFlush | ❌ | ❌ | ❌ | — | ❌ | dc civac 被内核拦截 |
| 时延检测（无陷阱页） | ❌ | ❌ | ❌ | — | ❌ | 缓存效应 <10ns vs 噪声 ~100ns, 信噪比不可用 |
| PMU HW (L1D/L2D/DTLB) | ❌ | ❌ | ❌ | — | ❌ | ARM task-context 隔离, 不计入目标 PMU |
| PMU RAW (0x31 REMOTE_ACCESS) | ❌ | ❌ | ❌ | — | ❌ | 受控实验无信号, 仍受 task-context 限制 |
| PMU uncore (LLCC/system-wide) | ❌ | ❌ | ❌ | — | ❌ | SELinux 阻断 pid=-1, sysfs 不可读 |
| perf_event (tracepoint) | ❌ | ❌ | ✅ | — | ❌ | raw_syscalls 不生成事件 |
| /proc/self/io | ❌ | ❌ | ❌ | — | — | 不改变目标 I/O 计数器 |

---

## 15. 最终检测能力总结

| 攻击类型 | 用户态检测 (防御者非root) | 攻击者权限 | root 检测 |
|---------|-----------|:---:|---------|
| `process_vm_readv` 直接读 | **PerfEvent跨通道** + **时延检测** + **mincore** | root | **kprobes** |
| pagemap 预探测 + 批量读 resident | **陷阱轮换** (竞态窗口) | root | **kprobes** |
| 逐页 pagemap + readv (99.87% 规避陷阱) | **几乎无法检测** (31/23936 误读，仅 PMU 级残留) | root | **kprobes** |
| L3 + 使用窃取数据 (渲染/外泄) | **蜜罐令牌** (数据溯源) | root | **kprobes** |
| `process_vm_writev` (写) | **Canary** + **GuardPage** | root | **kprobes** |
| pagemap 侦察 (只读不写) | 无法检测 (无痕侧信道) | root | 无法检测 |

### 15.1 核心结论

1. **用户态可检测的四层攻击**（攻击者均为 root）：
   - L1 直接读：PerfEvent 跨通道、时延检测、mincore（防御者自检）均可检测
   - L2 预探测+批量读：陷阱轮换制造竞态窗口
   - L3 逐页 pagemap+readv：用户态内存副作用检测的终点——竞态窗口仅 ~3-6μs
   - L4 L3 + 使用窃取数据：应用层蜜罐（数据溯源），将检测从内存层提升到数据使用层

2. **时延检测是 PerfEvent 的有力补充**：纯用户态 `clock_gettime` 计时，无需 `CONFIG_PERF_EVENTS`，信噪比充足（~20-50x），但必须配合陷阱页使用

3. **ARM64 硬件 PMU 方案不可行（经严格验证）**：五个探索方向全部失败。根因：ARM PMU task-context 隔离 + SELinux 阻断系统级访问

4. **所有 fault 类检测的进化链**（攻击者始终 root，防御者非 root）：

   ```
   直接读 → pagemap预探测 → 陷阱轮换 → 逐页pagemap → syscall监控(需root)
     ✅         ✅           ✅(竞态)    ❌(用户态)     ✅(root)
                                            ↓
                                     数据使用 (渲染/外泄)
                                            ↓
                                 应用层蜜罐 ✅(数据溯源)
   ```

5. **用户态攻防终局**：攻击者采用逐页 pagemap + readv 可将内存副作用压缩至极低水平（99.87% 规避率，31/23936 误读），但**不可完美消除**——残留的 D5 DTLB +101%、D6 RefLat -33% 等 PMU 级信号仍可被统计检测捕获。更重要的是，检测可以在数据使用层继续进行——将问题从"检测内存被读"转变为"检测数据被用"。

6. **pagemap 的能力边界**：`/proc/<pid>/pagemap` 可以区分驻留页/非驻留页（帮助攻击者绕过陷阱页），但不能区分合法数据/蜜罐数据（两者都是驻留页中的字节）。这是防御方在应用层的不对称优势。

---

## 附录：代码文件修改记录

| 文件 | 修改内容 |
|------|---------|
| `attacker.c` | +`#include <stdint.h>`; +`#include <fcntl.h>`; +`do_probe()` pagemap 探测命令 |
| `detect.h` | 独立 mincore_region → trap_indices[128]/trap_count/round; +MinFlt 字段; +PerfEvent 跨通道字段 |
| `detect.c` | 陷阱页散布于 ref_region; 修复 detect_swap/detect_mincore 先查后收; 陷阱轮换; +detect_minflt; +detect_perf（跨通道测序） |
| `detector.c` | CacheFlush 不触发自毁; 输出陷阱页数; 7→8 个检测方法 |
| `CMakeLists.txt` | 移除 `-llog` 链接 |
