---
title: ARM64 Android 跨进程内存读写检测——方法、缺陷与对抗
date: 2026-06-04 17:00:00
tags:
  - Android
  - ARM64
  - 内存检测
  - 跨进程
  - Linux内核
  - 逆向工程
  - 游戏安全
categories:
  - 安全分析
description: 系统研究 Android ARM64 平台上跨进程内存读写的可检测性，覆盖 mincore 自检、PerfEvent 跨通道测序、PMU 硬件计数器、kprobes 内核挂钩等十余种检测方法，分析各方案的优缺点与对抗手段。
---

# Android process_vm_readv/writev 检测项目分析

> 自拟题目: **"ARM64 Android 跨进程内存读写检测：方法、缺陷与对抗"**

## 项目概述

本项目实现了一套 Android ARM64 平台上对 `process_vm_readv` / `process_vm_writev` 跨进程内存读写的检测框架，包含：
- **detector**: 检测守护进程，监控自身内存是否被外部进程读写
- **attacker**: 攻击模拟工具，使用 `process_vm_readv/writev` 读写目标进程内存

## 检测方法总览

| 方法 | 原理 | 检测读 | 检测写 | 本设备实测 |
|------|------|:---:|:---:|------|
| **mincore** | MADV_DONTNEED 回收页面后检查是否变 resident | ✅ | ❌ | ✅ 有效 |
| **Canary** | 内存末尾嵌入校验值，比对是否被篡改 | ❌ | ✅ | ✅ 有效 |
| **Swap** | MADV_PAGEOUT 换出后检查 VmSwap 是否下降 | ❌ | ❌ | ❌ process_vm_readv 不走 swap-in |
| **Referenced** | /proc/smaps Referenced 位检查 | ❌ | ❌ | ❌ FOLL_REMOTE 不置 Accessed |
| **CacheFlush** | dc civac 刷缓存后测访问延迟 | ❌ | ❌ | ❌ 该设备内核拦截用户态 dc civac |
| **GuardPage** | PROT_NONE 守卫页包围数据区 | ❌ | ✅ | 仅写检测有效 |

## mincore/pagemap 绕过分析

### 关键前提：mincore() 不能跨进程探测

`mincore()` 只能检查**调用者自身**地址空间的 PTE。外部攻击者无法用 `mincore()` 探测目标进程的内存驻留状态。跨进程驻留探测的唯一用户态手段是 `/proc/<pid>/pagemap`（需 root 权限或相同 UID）。

**权限模型**：本文中攻击者始终为 **root 权限**，防御者为 **非 root 用户权限**。攻击者通过 `/proc/<pid>/pagemap` 实现跨进程内存布局探测。

### 原始绕过 (独立 mincore_region)

攻击者通过 `/proc/<pid>/pagemap` 探测目标进程内存布局（bit 63 = page present）：
- 发现连续 2MB evicted 区域 → 这是独立的 `mincore_region` → 直接跳过
- 读其他 resident 页面 → 不触发任何检测

**注意**：防御者自身使用 `mincore()` 检测自己内存的驻留状态（合法且有效），攻击者的探测手段始终是 pagemap。

### 修复1: 陷阱页散布

取消独立 `mincore_region`，改为在 `ref_region` (2MB 数据区) 内散布 64 个陷阱页。

**攻击者 pagemap 视角**:
```
X..............X......X......X......X......X......X......X......
```
(X = 陷阱/evicted, . = 数据/resident)

攻击者需逐页探测 512 次才能避开所有陷阱。

**限制**: 陷阱位置静态，攻击者探测一次即可永久避开。

### 修复2: 陷阱轮换

每轮扫描后：
1. 恢复旧陷阱页（写入数据使其变 resident）
2. 用 `cntvct_el0 ^ round` 做种子重新随机选取陷阱
3. 回收新陷阱页

```c
uint64_t tsc;
__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(tsc));
int seed = (int)((tsc ^ (tsc >> 12) ^ (ctx->round * 0x9E3779B9)) & 0xFFFF);
```

**效果**: 陷阱位置每轮变化，攻击者探测立即过时。

### 残留绕过

pagemap 读取极快（pread 单次 8 字节、无需遍历页表），攻击者可在轮换间隔内完成：
1. 读 `/proc/<pid>/pagemap` → 获知当前陷阱分布
2. 读安全页 → 获取数据
3. 在下一轮轮换前完成

**根本原因**: pagemap 只读页表查询，不修改 PTE、不触发缺页、不改变任何被监控页状态。实测验证见 ["perf_event 侧信道测序 → 绕过分析"](#perfevent-侧信道测序)。

**注意**：防御者自身的 `mincore()` 检测是无痕的（只查询自己 PTE），但攻击者无法用 `mincore()` 跨进程探测——攻击者唯一可用的无痕探测手段是 pagemap（需 root）。

## 新增检测方法: MinFlt

### 原理

`process_vm_readv` 内核路径:
```
process_vm_readv → pin_user_pages_remote → __get_user_pages → faultin_page
→ handle_mm_fault → 目标进程 min_flt++
```

读已回收 (MADV_DONTNEED) 页面会触发目标进程 minor page fault。监控 `/proc/self/stat` 的 `min_flt` 字段可检测。

### 实现

```c
static long get_min_flt(void) {
    FILE *fp = fopen("/proc/self/stat", "r");
    long min_flt;
    fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %ld", &min_flt);
    fclose(fp);
    return min_flt;
}
```

每轮 `delta = now - prev_min_flt - expected_self_faults`，`delta > 0` 则报警。

### 实测基线

无攻击时每轮 `min_flt +64~67 (self:~74)`。detector 自身活动产 64-67 faults/round。噪声 ~±7。外部需读 >7 页才超噪底。

### 局限

- 信噪比低：少量读取 (< 7 页) 时信号淹没在噪声中
- 读 resident 页不产生 fault，不触发
- pagemap 预探测 + 仅读 resident 页可绕过（与 PerfEvent 相同根局限，详见下文"绕过分析"）
- 与 mincore 互补：mincore 检读陷阱页，MinFlt 检大规模读取

## perf_event tracepoint 尝试

### 方案

用 `perf_event_open(PERF_TYPE_TRACEPOINT, raw_syscalls/sys_enter)` 全局捕获 syscall：
```
raw_syscalls/sys_enter → 过滤 id==270 (process_vm_readv) + args[0]==本进程PID → 检测
```

### 实测结果

- `perf_event_open` 成功，ring buffer 收到事件
- 但所有事件的 `id` 字段恒为 98 (futex)，从未出现 270
- ftrace 直接验证：`echo 1 > raw_syscalls/enable` → `entries-written: 0`
- **根因**：该 Android 内核 (5.4.210) 的 `raw_syscalls` tracepoint 不生成事件（`CONFIG_FTRACE_SYSCALLS` 未完整配置）

### 结论

perf_event tracepoint 方案在具备完整 syscall tracepoint 支持的内核上可用，但本设备不支持。代码已移除。

## kprobes 检测方案

### 原理

不依赖 tracepoint，直接用 kprobe 钩在内核函数入口：
```
__arm64_sys_process_vm_readv → process_vm_rw_core(pid, ...)
```

`process_vm_rw_core` 第一个参数就是目标进程 PID，kprobe 捕获 `%x0` 即可。

### 设置

```bash
echo 'p:vmrw process_vm_rw_core pid=%x0' > /sys/kernel/tracing/kprobe_events
echo 1 > /sys/kernel/tracing/events/kprobes/vmrw/enable
```

### 实测输出

```
attacker-30442 → vmrw: process_vm_rw_core  pid=0x76df (=30431, detector PID)
attacker-30445 → vmww: __arm64_sys_process_vm_writev  (writev 也捕获)
```

**精确捕获到 attacker 对 detector 的 process_vm_readv 和 process_vm_writev 调用。**

### 特点

| 优点 | 缺点 |
|------|------|
| 直接钩内核函数，攻击者无法规避 | 需要 root 权限设置 kprobe |
| 零误报（只捕获目标 PID 匹配的事件） | 需要内核支持 kprobes (`CONFIG_KPROBES`) |
| 同时检测 readv 和 writev | trace buffer 需要定期读取和清空 |
| 不依赖页面状态变化，不受 pagemap 探测影响 | 内核函数名可能因版本不同而变化 |

### kprobe vs mincore 检测对比

| | kprobes | mincore |
|------|---------|---------|
| 检测原理 | 直接钩 syscall 入口 | 检测页面常驻变化 |
| 能否被 pagemap 绕过 | ❌ 不可绕过 | ✅ 可绕过 |
| 是否误报 | 否 | 是 (CacheFlush 始终误报) |
| 需要 root | ✅ | ❌ |
| 检测 writev | ✅ | ❌ |

## perf_event 侧信道测序

### 核心发现

perf_event 和 /proc/self/stat 对 `process_vm_readv` 触发的 minor page fault **不一致**：

| 测量通道 | process_vm_readv 后 | 原因 |
|---------|-------------------|------|
| `/proc/self/stat` min_flt | **有增量** (+N faults) | `mm_account_fault` 通过 `FOLL_REMOTE` 路径累加到目标 mm 关联的 task |
| `perf_event(PERF_COUNT_SW_PAGE_FAULTS_MIN)` | **无增量** | `perf_sw_event()` 在 attacker 的 task context 触发，不递送到目标进程 perf counter |

### 跨通道检测原理

利用两个通道的差异构成侧信道：

```
external_faults = delta_min_flt - delta_perf_faults
if external_faults > 0 → process_vm_readv 检测到!
```

- `perf_event` 计数**仅自身 task context** 内的 fault（外部攻击不影响）
- `/proc/self/stat` 计数**全部** fault（包括外部 `FOLL_REMOTE` 触发的）
- 差值自动抵消自身活动，无需精确校准 `expected_self_faults`

### 实现

用 `perf_event_open` 创建编组计数器：

```
Leader: PERF_COUNT_SW_PAGE_FAULTS_MIN  (fault 计数)
Member: PERF_COUNT_SW_TASK_CLOCK       (纳秒级时钟)
```

`PERF_FORMAT_GROUP` 原子读取 `{faults, task_clock}`。每轮同时读取 `/proc/self/stat` min_flt 和 perf_event，比较两者增量。

### 实测结果

**无攻击基线** (每轮 ~3-4ms task_clock，两侧完全同步):

```
Round 2   stat:+64  perf:+64  ext:+0   clock:3929us
Round 3   stat:+64  perf:+64  ext:+0   clock:3605us
Round 4   stat:+64  perf:+64  ext:+0   clock:3479us
Round 5   stat:+64  perf:+64  ext:+0   clock:3430us
Round 6   stat:+64  perf:+64  ext:+0   clock:3754us
Round 7   stat:+64  perf:+64  ext:+0   clock:4195us
```

**攻击** — attacker 对 ref_region 执行 200 页 (819200 bytes) process_vm_readv，命中 25/64 trap pages:

```
--- 攻击发起 ---
$ ./attacker 31300 read 0x6fced3f000 819200
readv @0x6fced3f000: 819200 bytes: AA AA AA AA AA AA AA ...

--- Detector Round 8 ---
Method         | Detected   | Detail
Referenced     | NO         | no reference
Swap           | NO         | swap stable: prev=1024 now=1024 kB
mincore        | YES        | 25/64 trap pages resident
CacheFlush     | YES        | cache hit: 14 cycles        (已知误报)
Canary         | NO         | canary intact
GuardPage      | NO         | guard layout active (PROT_NONE at edges)
MinFlt         | YES        | min_flt spike +89 (self ~74, excess 15)
PerfEvent      | YES        | stat:+89 perf:+64 ext:+25 clock:4101us
-----------------------------------------------------------------
[!!!] 3 non-cache method(s) detected attack!
[!!!] EMERGENCY WIPE: sensitive memory zeroed
[!!!] Exiting for safety.
```

**关键对比**:

| 回合 | stat (含外部) | perf (自身) | ext (外部fault) | 判定 |
|------|:---:|:---:|:---:|------|
| 基线 R2-R7 | +64 | +64 | **0** | 正常 |
| 攻击 R8 | **+89** | +64 | **+25** | ✅ 检测 |

ext:+25 精确等于 mincore 的 25/64 trap pages resident，证明每个外部 fault 都对应一个被 `process_vm_readv` 读回的陷阱页。

### 对比 MinFlt

| | MinFlt (/proc/self/stat) | PerfEvent 跨通道 |
|---|---|---|
| 检测原理 | 单通道绝对值 vs 预期校准值 | 双通道差值 |
| 需要校准 | ✅ 需要 `expected_self_faults` | ❌ 自动抵消自身活动 |
| 信噪比 | 低 (excess=2 时检测，接近噪底) | 高 (ext=+25 时检测，信号清晰) |
| 误报风险 | 自身活动波动导致误报 | 低 (两边同时增加，差值不变) |

### 绕过分析

**pagemap 探测是否可检测？** 实测验证——attacker 仅调用 pagemap probe，不执行 readv：

```
# pagemap probe (只读页表，不读内存):
$ ./attacker 32103 probe 0x75fc7bb000 256
.....X...X...........X...X...........X...X...........X...X......
Result: 8 evicted (X), 56 resident (.)

# Detector 对应轮次:
Round    PerfEvent
R2-R13   ext:+0  (全部 12 轮，无任何检测)
```

→ **pagemap 探测不可检测**。`pagemap_read()` 只读内核页表（`mmap_read_lock` + PTE 遍历），不修改 PTE、不触发 fault、不在目标 task context 产生 perf event。

**pagemap + 选择仅读 resident 页，能否绕过？** 实测对比：

```
pagamap 输出:  .....X...X...........X...X...........
               页0-4 resident    页5 trap  页10 trap
```

| 步骤 | 操作 | 攻击细节 | PerfEvent | 判定 |
|------|------|---------|:---:|------|
| 1 | pagemap probe | 识别 X (trap) vs . (resident) | ext:+0 | 探测无痕 |
| 2 | 读页0 (resident) | `readv @ref_addr 4096` | **ext:+0** | ❌ **绕过成功** |
| 3 | 读页5 (trap) | 无法测试——detector 在步骤2时因 Referenced 误报退出 | — | — |

**完整绕过链**:

```
1. pagemap probe  →  获知 X (evicted/trap) vs . (resident/data)
2. process_vm_readv 仅读 . (resident) 页  →  0 次 fault
3. detector: ext = 0, mincore 0 trap resident  →  无报警
```

448/512 页 (87.5%) 为 resident 数据页，可被安全读取。

**绕过的对抗——trap 轮换**:

攻击者必须 pagemap 探测后、下一轮轮换前完成读取。一旦轮换触发：
- 旧 trap 被 memset 恢复（变 resident）
- 新 trap 被 MADV_DONTNEED 回收（变 evicted）
- pagemap 探测结果立即过时

缩短 detector 扫描间隔可压缩攻击窗口（参数量为 `interval_ms`）。

**对比：fault 类检测的绕过难度**:

| 攻击方式 | ext 信号 | mincore | MinFlt | 备注 |
|---------|:---:|:---:|:---:|------|
| 直接读（无侦察） | ✅ +N | ✅ N traps | ✅ excess N | 必然撞 trap |
| pagemap → 仅读 resident | ❌ 0 | ❌ 0 traps | ❌ 0 excess | 精准避开所有 evicted |
| pagemap → 读 512 页全部 | ✅ +64 | ✅ 64 traps | ✅ excess | 读全量，100% 命中 trap |

### 局限

- 仅检测**读**（writev 不触发 page fault）
- 依赖 `CONFIG_PERF_EVENTS` 内核支持；`perf_event_paranoid` 必须 ≤ 1
- pagemap 预探测 + 仅读 resident 页可绕过（所有 fault 类检测的共同弱点）
- `perf_event` 自身 fault 不被外部影响是本方案的基石，如果未来内核改变会计方式可能失效

## ARM64 硬件 PMU 检测方案研究

### 测试环境

| 项目 | 值 |
|------|-----|
| SoC | Qualcomm (Cortex-A55 x4 + Cortex-A75 x2+) |
| PMU | ARMv8 PMUv3 |
| 内核 | 5.4.210-qgki |
| perf_event_paranoid | -1 |
| UID | 2000 (shell) |
| SELinux | Enforcing |
| 额外 PMU 设备 | armv8_pmuv3, llcc-pmu, cs_etm |

### 五个探索方向

#### 1. 系统级监控 (pid=-1, cpu=N)

绕过 task-context 隔离的最直接方法 -- 监控整个 CPU 而非特定进程。所有 CPU (0-7)、所有 event type 均返回 EACCES。

**结论**: SELinux 阻止了 shell 用户进行系统级 PMU 监控。即使 paranoia=-1。

#### 2. Qualcomm LLCC-PMU (系统级 Cache Controller)

LLCC (Last Level Cache Controller) PMU 是系统级 uncore PMU，理论上可观测所有处理器的缓存流量：

- 设备节点存在: /sys/devices/platform/soc/9095000.llcc-pmu
- 模块已加载: llcc_perfmon
- **sysfs type 文件不可读** (SELinux)
- **events 目录不存在** -- PMU driver 可能未完整注册事件
- 尝试 pid=-1 打开: 全部 EACCES

**结论**: LLCC-PMU 存在但用户态完全无法访问。

#### 3. ARMv8 RAW Event 编码探索

无法读取 /sys/bus/.../format/event 文件（SELinux），只能盲测 raw event 编码。

**少计数器测试（6个以内，避免 multiplexing 饥饿）**:

| 事件码 | 名称 | 自访问计数 | 备注 |
|--------|------|-----------|------|
| 0x11 | CPU_CYCLES | 376K delta | 正常工作 |
| 0x3100 | REMOTE_ACCESS? (shift 8) | 微弱 (172) | 仅 busy-loop 自身产生 |
| 0x03 | L1D_CACHE_REFILL | 始终 0 | 编码不匹配或未实现 |
| 0x08 | INST_RETIRED | 始终 0 | 编码不匹配 |
| 0x17 | L2D_CACHE_REFILL | 延迟激活 | multiplexing 调度到时才有值 |

**关键限制**: 打开超过约 8 个计数器后，raw events 因 multiplexing 饥饿全部归零。

**REMOTE_ACCESS (0x31) 深入测试**:

ARMv8 事件 0x31 定义 "来自其他处理器的访问" -- 检测跨进程内存访问最理想的 PMU 事件。

- config=0x0031: 打开成功，所有阶段 delta=0
- config=0x3100: 打开成功，初始观察有微弱增量（72-125），但**受控实验中攻击阶段与控制组无差异**（delta=0）

**结论**: 即使找到正确编码，REMOTE_ACCESS 仍受 task-context 限制。

#### 4. PERF_TYPE_HW_CACHE 测试

使用通用 cache 事件类型（type=3）:

- L1D_READ_ACCESS: 工作 (111K delta, 自访问)
- L1D_READ_MISS:   工作 (3K delta, 自访问)
- LL_READ_ACCESS:  **ENOENT** (该硬件不支持 LL cache 事件)
- LL_READ_MISS:    **ENOENT**
- DTLB_READ_ACCESS: 工作
- DTLB_READ_MISS:   工作

LL (Last Level) cache 事件不可用，无法通过通用接口监控 L3 缓存。

#### 5. 未知 PMU Type 8 & 10

PMU 枚举发现两个可打开但行为不明的 type：

| Type | pid=0 行为 | pid=-1 行为 | 推测 |
|------|-----------|-----------|------|
| 8 | 多种 event 产生有效计数 | EACCES | CPU PMU 别名或 DSU PMU |
| 10 | 所有 event delta=0 | EACCES | 可能是未初始化的 llcc-pmu |

### 跨进程攻击 PMU 信号 -- 严格受控实验

**实验设计**: 父进程 busy-loop 维持 CPU 上下文 + 四阶段对照:

- Phase 0: IDLE 基线（排除系统噪声）
- Phase 1: BUSY + child NO-OP（控制组: 排除父进程自身活动）
- Phase 2: BUSY + child process_vm_readv（实验组: 16 页）
- Phase 3: BUSY + child NO-OP（验证组: 确认信号回归基线）

**实测结果**（所有 HW/RAW 计数器）:

| Counter | IDLE | CTRL | ATTACK | VERIFY | 判定 |
|---------|------|------|--------|--------|------|
| HW_CACHE_MISS | 0-428 | 0-301 | 0 | 0-679 | 无差异 |
| HW_BUS_CYCLES | 0-516K | 0-1.4M | 0-1.37M | 0-708K | 无差异（正比于 busy-loop 时长） |
| REMOTE_0x3100 | 0 | 0 | 0 | 0 | **无信号** |
| BUS_0x1900 | 0 | 0 | 0 | 0 | **无信号** |
| SW_FAULTS | 0 | 0 | 0 | 0 | **无信号**（perf_event 不计 FOLL_REMOTE） |

**结论: 所有 HW/RAW 计数器在攻击阶段与控制组无显著差异。** 父进程 PMU 只反映自身 busy-loop 活动量，不反映子进程跨进程内存访问。

### 根因分析

ARM64 PMU task-context 隔离机制，三个潜在绕过路径均被阻塞：

| 绕过路径 | 状态 | 阻塞原因 |
|---------|:---:|------|
| 系统级监控 (pid=-1) | FAIL | SELinux EACCES |
| llcc-pmu (uncore) | FAIL | sysfs 不可读 + pid=-1 EACCES |
| REMOTE_ACCESS event (0x31) | FAIL | 仍受 task-context 限制 |
| 缓存一致性流量 (HW_BUS_CYCLES) | FAIL | 仅计数本 task 调度时段 |

软件事件对照：

| 事件 | 计入 target? | 原因 |
|------|:---:|------|
| task_struct->min_flt | Yes | mm_account_fault 通过 FOLL_REMOTE mm 关联 |
| PERF_COUNT_SW_PAGE_FAULTS_MIN | No | perf_sw_event() 在 attacker context |
| L1D/L2D_CACHE_REFILL (PMU) | No | PMU 硬件仅计数本 task 调度时段 |
| BUS_ACCESS (PMU) | No | 同上 |
| REMOTE_ACCESS (PMU) | No | 同上（即使正确编码） |
| LL_CACHE_MISS (PMU) | No | 该事件不存在于本硬件 |

### PMU 研究最终结论

**ARM64 硬件 PMU 在用户态下无法检测 process_vm_readv。** 这不是权限问题（paranoia=-1 名义上允许所有事件），也不是编码错误（通过各种编码尝试和对照实验排除），而是 ARM PMU 架构的根本设计 -- task-context 隔离使目标进程的 PMU 无法感知其他进程的微架构事件。

系统级 PMU（uncore/DSU/LLCC）理论上可绕过隔离，但 SELinux 阻止了用户态访问。root 权限下这些方案可能可行，但用户态下唯一有效方案是已验证的 **PerfEvent 跨通道测序**（利用 /proc/stat 与 perf_event 软件计数器对 FOLL_REMOTE 会计不一致的侧信道）。

## 内存访问时延检测

### 原理

不依赖 perf_event 或 mincore，纯用户态计时区分驻留页与非驻留页：

```
非驻留页: MADV_DONTNEED 回收 → 访问触发缺页 → ~2000-5000ns
驻留页:   已在物理内存中 → 访问走缓存 → ~50-150ns
差异: ~20-50x，clock_gettime 分辨率 (~50ns) 足以分辨
```

### 校准数据

| 访问类型 | 时延 | 说明 |
|---------|------|------|
| 驻留页 (缓存命中) | p50=52ns, p99=105ns | 直接 L1 缓存访问 |
| 非驻留页 (缺页) | min=1823ns, median=1927ns | 内核缺页处理 |
| clock_gettime 开销 | 52-104ns | 测量噪声 |
| 检测阈值 | 5x resident p99 = 525ns | 动态校准 |

### 检测流程

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

### 实测结果

- **基线（无攻击）**: 20 轮 Fast=0，零假阳性
- **攻击检出**: 匹配 attacker 读 16 页命中约 4 个 trap（25% 密度）
- **信号对比**: 驻留页 156ns vs 缺页 1875ns，12:1 信噪比

### 优势与局限

**优势**: 不需要 CONFIG_PERF_EVENTS，不需要 mincore() 系统调用，纯用户态，attacker 无法感知（无 syscall 痕迹）。

**局限**: 与所有 fault 类检测共享同一个根本弱点——依赖非驻留陷阱页。攻击者可通过 `/proc/<pid>/pagemap` 预探测避开（mincore 不能跨进程）。

## 陷阱轮换 vs pagemap 预探测——竞态窗口测试

### 架构说明

**以下竞态测试采用独立进程架构**：防御者进程（非 root 用户）和攻击者进程（root 权限）完全独立，不共享内存。防御者启动后输出其 PID 和内存地址；攻击者通过命令行参数获取目标信息，使用 `/proc/<pid>/pagemap`（root 权限）做跨进程探测，使用 `process_vm_readv` 做跨进程读取。

### 测试设计

Defender 每轮轮换陷阱页（MADV_DONTNEED 新集合），Attacker 先 pagemap 预探测再长时间读取。

```
Defender: ─── 陷阱集A ─── 陷阱集B ─── 陷阱集C ───
           | 200ms | 200ms | 200ms |

Attacker:  [pagemap探测]────── 逐页 process_vm_readv ──────]
           |← 竞态窗口 (3-320ms) →|
```

### 实测结果（独立进程，攻击者 root，防御者 user）

测试参数：256 页缓冲区，64 个陷阱页 (25%)，200ms 轮换周期，64 页读取量。

| 页间延迟 | 读取窗口 | vs 200ms轮换 | readv故障 | excess min_flt | 检出 |
|:---:|------|:---:|:---:|------|:---:|
| 0ms | ~3ms | 远小于 | 0 | 0 | ❌ 0% |
| 1ms | ~67ms | 小于 | 0 | 0 | ❌ 0% |
| 2ms | ~131ms | 临界重叠 | 0 | 0 | ❌ 0% |
| 3ms | ~195ms | 接近重叠 | 0 | 偶尔+43 | ⚠️ 20% |
| 5ms | ~323ms | **完全跨越** | 0 | 偶尔+43 | ⚠️ 20% |

**与 fork+MAP_SHARED 模拟的关键差异**：原始 fork 模拟实验报告了 93% 检出率 (5ms 延迟)。独立进程架构下，攻击者的 pagemap 探测直接读取目标进程页表（一次 pread 8 字节），探测速度极快 (~0.7ms 扫描 256 页)，而批量 readv 之后无回读确认。实际上 process_vm_readv 在命中已回收页时会触发 FOLL_REMOTE 缺页（目标 min_flt 增加），但 readv 本身返回成功（内核自动补页），攻击者侧无感知。**防御者侧的 min_flt 偶尔能捕获这些外部 fault，但信号不稳定。**

**注意**：此测试为 L2 级攻击（一次 pagemap 预探测 + 批量读取）。攻击者如果采用逐页 pagemap（L3），每页读取前重新探测，则连这些偶发的 min_flt 信号也会被消除。

## 逐页 pagemap——用户态攻防的终点

### 攻击升级

攻击者将"先探测再批量读"改为"每读一页前都通过 pagemap 检查"：

```
传统方案: pagemap(全部) → readv(p1) → readv(p2) → ... → readv(pN)
                              |← 竞态窗口可达数百ms →|

逐页方案: pagemap(p1)→readv(p1) → pagemap(p2)→readv(p2) → ...
                 |← 17μs →|          |← 17μs →|
```

**注意**：跨进程场景下攻击者使用的是 `/proc/<pid>/pagemap`（root 权限），而非 `mincore()`。`mincore()` 只能检查调用者自身地址空间，无法跨进程探测。

### 实测数据

**场景**：防御者 200ms 轮换 64 个陷阱页（512 页缓冲区，12.5% 陷阱密度）。攻击者逐页 pagemap 判断后再决定是否 readv。

```
攻击者侧 — 逐页 pagemap 判断 + 跳过非驻留页
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Initial probe: 448 resident, 64 evicted (12.5% traps)

逐页结果 (512 页全量):
  pagemap → resident → READ  → OK:   448 页 (87.5%)
  pagemap → evicted  → SKIP → -:     64 页 (12.5%)
  readv 失败:                           0 页 (0%)

  Avg pagemap 耗时: 1871 ns/page
  Avg readv 耗时:   ~3300 ns/page
  陷阱规避率:      100% (64/64 traps correctly skipped)

防御者侧
━━━━━━━━
  Baseline:        64 min_flt/round
  trap_resident:    0 (全程)
  min_flt delta:   64 (=baseline)
  excess:           0
  Status:          - (无检出)

→ 逐页 pagemap 规避率 99.87%（本次 512 页扫描零误读）。但六维度 PMU 实验中 47,872 次 pagemap 探测 + 23,936 次读取累计 31 次误读蜜罐页（0.13% 误差率），证明大规模操作下仍有零星陷阱命中。
  防御者毫不知情。
```

### 逐页判断时序分析

```
Page 0  (resident): pagemap=1871ns → READ→OK = 5782ns total
Page 7  (evicted):  pagemap=2396ns → SKIP         (不读)
Page 15 (evicted):  pagemap=2240ns → SKIP         (不读)
...
Page 504(resident): pagemap=1302ns → READ→OK = 3490ns total
Page 511(evicted):  pagemap=1302ns → SKIP         (不读)
```

每页 pagemap 判断耗时中位数 ~1871ns，加上 readv 后总延迟 ~3-5μs。陷阱页仅需 pagemap 查询（~1.9μs），无需 readv。

### 竞态窗口计算（实测）

```
逐页窗口 = pagemap pread(8 bytes) + (readv if resident) = ~3-6μs
轮换周期 = 200ms = 200,000μs
命中概率 = 4 / 200,000 = 0.002%
→ 约 50,000 次读取才期望命中 1 次陷阱
```

**逐页 pagemap 将竞态条件压缩至极低概率，但未完全消除。** 小规模测试（512 页单次扫描）中零误读；但六维度 PMU 实验中 47,872 次 pagemap 探测累计 31 次误读蜜罐页（0.13% 误差率），且产生 D5 DTLB +101% 的 PMU 级残留信号。0ms busy-loop 轮换下 ~12M 次操作中 readv 返回零失败，是因为 process_vm_readv 在命中已回收页时内核自动补页（返回成功），攻击者无法从返回值判断是否误读陷阱。

### 代价

| | 批量预探测 | 逐页 pagemap |
|------|:---:|:---:|
| 竞态窗口 | 3-320ms | **13-19μs** |
| 陷阱命中率 | 0-93% | **<0.01%** |
| 内存侧信道可检测 | ✅ 可检测 | **❌ 不可检测** |
| syscall 次数 (64页) | 65 | **128** |
| syscall 特征 | 低 | **高** (交替 pagemap+readv 模式) |
| 读取吞吐 | 高 | 降低 ~50% |

### 攻防升级链

```
L1  直接 readv           →  PerfEvent跨通道 / 时延检测     ✅ 用户态可检测
L2  pagemap预探测+批量读  →  陷阱轮换 (竞态窗口)           ✅ 用户态可检测
L3  逐页 pagemap+readv   →  内存驻留检测几乎失效           ⚠️ 仅 PMU 级残留
                            syscall 模式监控               🔒 需 root
L4  —                    →  kprobes/eBPF 钩内核            🔒 需 root
```

### pagemap 为什么不可检测

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

**关键区别**：`mincore()` 用于防御者自检（合法有效），`/proc/<pid>/pagemap` 用于攻击者跨进程探测（需 root）。两者都是只读页表查询，零副作用。

### 用户态攻防终止线

逐页 pagemap + process_vm_readv 将可检测的"缺页"替换为几乎不可检测的"页表只读查询"。从受害者视角，`/proc/self/stat` 和 `perf_event` 计数器几乎无变化——但并非绝对零信号：六维度 PMU 实验中 pagemap 模式仍有 31 次误读（0.13%），D5 DTLB Walk +101%、D6 RefLat -33%。**攻击者无法完美隐身，但残留信号极其微弱，仅 PMU 级别的统计检测可能捕获。**

### 极限竞态测试

使用独立进程架构测试：防御者进程（非 root 用户）运行陷阱轮换，攻击者进程（root 权限）通过 `/proc/<pid>/pagemap` 逐页探测后 `process_vm_readv`。512 页缓冲区，64 陷阱页 (12.5%)。

| 轮换速度 | 持续时间 | 攻击读取量 | 正确跳过 | readv 失败 | 平均竞态窗口 | 实测 |
|---------|---------|-----------|---------|-----------|------------|------|
| 200ms | 10s | 3.47M | 12.11% | 0 | 2.5μs | **0 失败** |
| 50ms | 10s | 3.01M | 12.67% | 0 | 2.9μs | **0 失败** |
| 10ms | 10s | 2.97M | 12.98% | 0 | 2.9μs | **0 失败** |
| **0ms (忙循环)** | **10s** | **2.15M** | **19.86%** | **0** | **3.9μs** | **0 失败** |

**总计**: ~11.6M 次 pagemap+readv 操作，**0 次 readv 失败**。

**0ms 轮换解释**：defender 去掉 `usleep`，持续 busy-loop evict → touch → evict → ... 每轮约 1.07ms。攻击者逐页 pagemap+readv，每页竞态窗口 ~3.9μs。在总计 10 秒、2.15M 次读取中，readv 从未失败，证明 pagemap 探测后到 readv 之间的窗口太窄，defender 的 madvise 无法在这个窗口中完成对该特定页的回收。

**核心理由**：每个 page 的竞态窗口（pagemap pread → readv）只有 ~3-4μs，而 defender 的 madvise 回收一个 page 也只需 ~1μs。两个窗口重叠的概率 = (3-4μs) × (64 页/轮 × 1μs/页) / (轮周期)² ≈ 极微小。

**结论**：L3 逐页 pagemap+readv 在内存层**几乎不可检测**。小规模扫描中陷阱规避率极高（99.87%+），但仍存在非零误读率（31/23,936 = 0.13%，六维度 PMU 实验数据）。竞态窗口物理存在：~3-6μs 的 pagemap→readv 间隙中，defender 可能恰好回收目标页。readv 返回成功不代表未命中陷阱（内核自动补页）。**攻击者无法完美隐身，残留信号仅 PMU 级统计检测可能捕获。**

要检测此类攻击，必须走 root 路径（kprobes/eBPF 钩 `process_vm_rw_core`）或应用层蜜罐（数据溯源）。

## 应用层蜜罐——数据溯源检测

### 核心洞察

**把问题从"检测内存被读"转变为"检测数据被用"。**

```
传统方法 (内核层):  内存访问 → 追踪内核副作用 (缺页/缓存/PMU)
                          ↓ 逐页 pagemap 可消除所有内存副作用
                          ↓ 用户态检测终点

蜜罐方法 (应用层):  内存访问 → 获取数据 → 使用数据 → 产生可观测副作用
                                               ↑
                                          在这里检测!
```

**关键不对称优势**: `pagemap`（攻击者跨进程探测）能区分驻留页 vs 非驻留页（躲避陷阱页），但**不能区分合法数据 vs 蜜罐数据**（两者都是驻留页中的普通字节）。防御者自身的 `mincore()` 同样只能做驻留/非驻留判断，没有语义理解能力。

### 蜜罐令牌结构

```c
#define HONEYPOT_MAGIC 0x484F4E4559504F54ULL  // "HONEYPOT"

struct HoneypotToken {
    uint64_t magic;      // 蜜罐标识 (固定魔数)
    uint64_t region_id;  // 内存区域标识 (溯源到具体数据区)
    uint64_t token_seq;  // 区域内序号
    uint64_t checksum;   // HMAC-like 校验 = hash(magic|region_id|seq|secret)
};
```

每个会话使用随机 `secret`，攻击者即使知道令牌格式，没有 `secret` 也无法区分真实令牌和随机数据（假阳性不可区分）。

### 三种蜜罐模式及实测

#### MODE 1: 静态令牌嵌入 (数据溯源)

```
Defender:  在敏感缓冲区嵌入令牌 (与合法数据交织, 无法从字节区分)
Attacker:  逐页 pagemap + process_vm_readv (root) → 读取全部内存
           → 将数据写入输出信道 (模拟外泄/渲染)
Defender:  扫描输出信道 → 检测令牌签名 → 确认内存被读取
```

**实测结果** (`honeypot_test mode 1`):
```
Session secret: 0x6a227b5b4f779cf3
[Defender] Embedded 16 tokens in 1048576-byte buffer
[Defender] Read 1048576 bytes from exfiltration channel

*** MEMORY READ DETECTED! ***
16 honeypot tokens found in attacker's output
Data provenance confirmed: region_id=1
```

**16/16 令牌全部检出**。攻击者无法用 mincore 区分令牌页（全部在驻留页中）。

#### MODE 2: Liveness Check (令牌逃逸检测)

```
Defender:  创建 3 个区域 (region 100/200/300), 各有独立令牌
           定期扫描外部监控信道 (模拟网络流量/日志监控)
Attacker:  L3 攻击 (逐页 pagemap + readv) — 此前认为不可检测
           → 将窃取的数据写入监控 buffer
Defender:  Liveness 扫描 → 检测到令牌 → 确认内存被读
```

**实测结果** (`honeypot_test mode 2`):
```
Region 100: 16 tokens
Region 200: 16 tokens
Region 300: 16 tokens

Round    Status               Details
0        clean                No tokens detected
1        *** BREACH! ***      Tokens detected in monitor buffer
  → 1 tokens from region(s): 100
  → L3 attack (per-page mincore) DETECTED via data provenance!
```

**L3 攻击被检测到**。逐页 pagemap 可以在内存层消除所有副作用，但无法阻止数据在使用层被追踪。

#### MODE 3: 自反噬陷阱值 (使用即触发)

在内存中放置特殊构造的值，攻击者解释并使用时产生可观测副作用：

```
struct FakePlayerData {
    char name[16];
    float x, y, z;       // 位置
    int health;
    uint64_t ability_ptr; // ← 蜜罐: 指向哨兵页
};
```

三种自反噬机制:
1. **指针陷阱**: `token = &monitored_page`, 攻击者解引用 → 访问被监控页 → `userfaultfd`/`pagemap` 可检测
2. **范围/索引陷阱**: `token = sentinel_array_index`, 攻击者用作索引 → 访问哨兵元素 → 可检测
3. **校验和陷阱**: token 嵌入数据结构, 攻击者输出中包含 token → 可鉴定来源

**实测结果** (`honeypot_test mode 3`):
```
[Defender] Every 8th player has ability_ptr → sentinel page at 0x757bbfa000
[Defender] If attacker dereferences ability_ptr, they access sentinel
[Defender] Sentinel access can be detected via pagemap monitoring
```

### 攻防进化链 (扩展)

```
L1: 直接 process_vm_readv
    → 陷阱页检测 (min_flt)                                   ✅ 可检测

L2: pagemap 预探测 + 批量读 resident 页
    → 陷阱轮换制造竞态窗口 (93% 检出 @ 5ms/页)              ✅ 可检测

L3: 逐页 pagemap + process_vm_readv (竞态窗口 ~17μs)
    → 内存副作用检测几乎失效，仅 PMU 级残留 (D5+101%)        ⚠️ 几乎不可检测

L4: L3 + 使用窃取的数据 (渲染/外泄/计算)
    → 应用层蜜罐 (数据溯源)                                  ✅ 可检测 ← 新增!
```

### 蜜罐 vs 陷阱页 对比

| 维度 | 陷阱页 (Trap Page) | 蜜罐令牌 (Honeypot Token) |
|------|-------------------|--------------------------|
| **检测层** | 内存管理层 (缺页) | 应用数据层 (数据使用) |
| **mincore 能否区分** | ✅ 能 (非驻留 vs 驻留) | ❌ 不能 (都是普通字节) |
| **竞态窗口问题** | 有 (轮换 vs 探测) | 无 (令牌始终在内存中) |
| **检测时机** | 访问时 (实时) | 使用时 (事后/实时) |
| **前提条件** | 攻击者读非驻留页 | 攻击者使用窃取的数据 |
| **绕过方法** | 逐页 pagemap (L3) | 不使用窃取数据 (但使用才能获益) |
| **实现复杂度** | madvise + mincore | 令牌嵌入 + 信道监控 |

### 局限与应对

1. **攻击者识别并过滤令牌**: 令牌格式已知 + secret 泄露 → 攻击者可过滤。**应对**: 每会话随机 secret，令牌与数据交织，过滤会破坏数据完整性

2. **攻击者不"使用"数据 (只读不输出)**: 若攻击者只读取数据但从不输出 → 令牌不逃逸。**应对**: 实际作弊工具必须输出 (ESP 渲染→GPU buffer, 雷达→网络), 总有一条可监控信道

3. **监控信道覆盖**: 需要覆盖所有可能的数据逃逸信道 (网络、文件、IPC、GPU)。**应对**: 这是工程问题而非原理问题；关键信道 (网络、文件 I/O) 相对容易监控

4. **假阳性**: 随机数据可能巧合匹配令牌魔数 (概率 ~1/2^64, 可忽略)。checksum 进一步将假阳性概率降至 ~1/2^128

### 代码

`honeypot_test.c` — 完整测试程序，包含三种蜜罐模式:
- `./honeypot_test 1` — 静态令牌嵌入 + 外泄信道检测
- `./honeypot_test 2` — Liveness 检查 (检测 L3 逐页 pagemap 攻击)
- `./honeypot_test 3` — 自反噬陷阱值 (指针/索引/校验和陷阱)

## 无需 root 权限的检测方法总结

用户态下（非 root）可用的检测方法及其效果：

| 方法 | 检测 readv | 检测 writev | 绕过难度 | 备注 |
|------|:---:|:---:|------|------|
| **PerfEvent** (跨通道) | ✅ | ❌ | 中等 | stat vs perf 差值; 自动抵消噪声; 信噪比最高 |
| **时延检测** | ✅ | ❌ | 中等 | 纯用户态计时; 无需 perf_event; 无需内核配置 |
| **mincore** (陷阱散布+轮换) | ✅ | ❌ | 中等 | 需 pagemap 探测+避开陷阱; 轮换提高难度 |
| **MinFlt** (/proc/self/stat) | ✅ (大量) | ❌ | 中等 | 少量读 (<7页) 信号淹没在噪声中 |
| **陷阱轮换** (竞态窗口) | ✅ | ❌ | 困难 (对批量读) | 逐页 pagemap 可消除竞态窗口 |
| **蜜罐令牌** (数据溯源) | ✅ | ❌ | 极高 (L4) | 检测数据"使用"而非内存访问; mincore 无法区分 |
| **Canary** | ❌ | ✅ | 低 | 唯一检测 writev 的用户态方法 |
| **GuardPage** | ❌ | ✅ | 低 | 检测数据区篡改 |
| Referenced | ❌ | ❌ | — | FOLL_REMOTE 不置 Accessed |
| Swap | ❌ | ❌ | — | 不走 swap-in 路径 |
| /proc/self/io | ❌ | ❌ | — | rchar/read_bytes 不变 |
| 时延检测 (无陷阱页) | ❌ | ❌ | — | 缓存一致性效应 <10ns, 淹没在噪声中 |
| PMU HW 计数 | ❌ | ❌ | — | ARM task-context 隔离 |

## 全部检测方法对比总表

| 方法 | 检测读 | 检测写 | 需root | 绕过难度 | 本设备可用 | 原理 |
|------|:---:|:---:|:---:|------|:---:|------|
| **kprobes** | ✅ | ✅ | ✅ | 不可绕过 | ✅ | 钩内核函数 process_vm_rw_core |
| **eBPF** | ✅ | ✅ | ✅ | 不可绕过 | 理论可用 | kprobe BPF 程序过滤 |
| **mincore** (陷阱散布+轮换) | ✅ | ❌ | ❌ | 中等 | ✅ | MADV_DONTNEED + mincore 驻留检测 |
| **时延检测** (陷阱页) | ✅ | ❌ | ❌ | 中等 | ✅ | 纯用户态 clock_gettime 计时; 无需 perf_event |
| **PerfEvent** (跨通道) | ✅ | ❌ | ❌ | 中等 | ✅ | /proc/stat vs perf_event fault 差值 |
| **MinFlt** | ✅ | ❌ | ❌ | 中等 | ✅ | /proc/self/stat min_flt 增量 |
| **陷阱轮换** (竞态窗口) | ✅ | ❌ | ❌ | 困难 (批量读) | ✅ | 缩短轮换周期→压缩安全窗口; 逐页mincore可消除 |
| **蜜罐令牌** (数据溯源) | ✅ | ❌ | ❌ | 极高 (L4) | ✅ | 检测数据使用而非内存访问; mincore免疫 |
| **Canary** | ❌ | ✅ | ❌ | 低 | ✅ | 内存校验值比对 |
| **GuardPage** | ❌ | ✅ | ❌ | 低 | ✅ | PROT_NONE 守卫页 |
| Referenced | ❌ | ❌ | ❌ | — | ✅ | /proc/smaps Referenced 位 |
| Swap | ❌ | ❌ | ❌ | — | ✅ | VmSwap 变化 |
| CacheFlush | ❌ | ❌ | ❌ | — | ❌ | dc civac 被内核拦截 |
| 时延检测 (无陷阱页) | ❌ | ❌ | ❌ | — | ❌ | 缓存效应 <10ns vs 噪声 ~100ns, 信噪比不可用 |
| PMU HW (L1D/L2D/DTLB) | ❌ | ❌ | ❌ | — | ❌ | ARM task-context 隔离, 不计入目标 PMU |
| PMU RAW (0x31 REMOTE_ACCESS) | ❌ | ❌ | ❌ | — | ❌ | 受控实验无信号, 仍受 task-context 限制 |
| PMU uncore (LLCC/system-wide) | ❌ | ❌ | ❌ | — | ❌ | SELinux 阻断 pid=-1, sysfs 不可读 |
| perf_event (tracepoint) | ❌ | ❌ | ✅ | — | ❌ | raw_syscalls 不生成事件 |
| /proc/self/io | ❌ | ❌ | ❌ | — | — | 不改变目标 I/O 计数器 |

## Honey Page 五代检测实验 & 六维度 PMU 统计检测

> 详细逐轮数据、源代码见 `docs/HONEYPAGE_EXPERIMENT_RESULTS.md`。本节提取核心结论和关键数据。

### G1-G5 五代实验摘要

**测试平台:** Android ARM64, Linux 5.4.210, 256 页/代, 8 轮 (4 基线 + 4 攻击)

| 世代 | 方法 | 可检测 | 关键信号 |
|------|------|:---:|------|
| G1 | 静态蜜罐页 | ⚠️ 弱 | min_flt 差异不显著 |
| G2 | MADV_DONTNEED 轮换 | ✅ 完美 | mincore: 0%→100%, SNR=∞ |
| G3 | PMU/min_flt 关联 | ✅ 100% | min_flt 1:1 per page |
| G4 | 三区访问时延 | ✅ 强 | Hot Ref +45%, Honey latency 方向反转 |
| G5 | Honey VMA | ✅ 放大 | scan time 26x |

**核心验证:**
- `process_vm_readv` 在 ARM64 Linux 5.4 上确实触发 DONTNEED 页的 minor fault
- 每个蜜罐页 → 精确 1 次 min_flt (1:1 对应)
- 被攻击页访问延迟**更低** (pre-fault 变热,~1500ns→~150ns)

### 六维度 PMU 统计检测

在 G2-G4 基础上引入 ARMv8 PMU 硬件计数器 (perf_event_open):

| 维度 | 名称 | 数据源 |
|------|------|--------|
| D1 | Honey Resident Count | mincore() |
| D2 | Recovery Rate | D1 / round_time |
| D3 | Minor Fault Delta | /proc/self/stat |
| D4 | Cache Miss | ARMv8 PMU: L1D refill |
| D5 | DTLB Walk | ARMv8 PMU: DTLB walk |
| D6 | Access Latency | 本核 load-to-use (热参考区+蜜罐区) |

**权限模型:**
```
防御者 (six_dim_detect)    shell 用户, 非 root
攻击者                      独立二进制, 独立进程, 独立地址空间
  ├── blind/smart          独立进程 (root 权限, 通过 su -c 提权)
  │                        使用 process_vm_readv, 无预探测
  └── pagemap              独立进程 (root 权限)
                           使用 /proc/<pid>/pagemap 跨进程探测
                           mincore 无跨进程能力, pagemap = root 专有的跨进程驻留查询
```

### 外部攻击者三模式对比

```
                     BLIND                   SMART                  PAGEMAP (root)
维度        baseline → attack   Δ%      baseline → attack   Δ%      baseline → attack   Δ%
────────────┼──────────────────────────┼──────────────────────────┼──────────────────────────
D1 HoneyR   │   0 → 256     ★★★ ∞     │   0 →   0     —  规避   │   0 →   0     —  规避
D3 MinFlt   │   0 → 255     ★★★ ∞     │   0 →   0     —  规避   │   0 →   0     —  规避
D4 $Miss    │ 153 → 242    +58% ★★★   │ 162 → 233    +44% ★★    │ 181 → 171     -6% ★
D5 DTLB     │  97 → 130    +34% ★★    │ 104 → 132    +27% ★★    │  62 → 126   +101% ★★★
D6 RefLat   │ 391 → 352    -10% ★     │ 390 → 267    -32% ★★    │ 332 → 222    -33% ★★
D6 HonLat   │1172 → 117    -90% ★★★   │1120 → 1146    +2% —     │1002 → 944     -6% ★
────────────┼──────────────────────────┼──────────────────────────┼──────────────────────────
Verdict     │    DETECTED (4/6)         │    BORDERLINE (3/6)       │    BORDERLINE (3/6)
```

**Pagemap 攻击者实际行为:**
```
pagemap 检查 47,872 次 → 23,967 页驻留 → 读 23,936 页参考区
蜜罐区: 仅 31 次误读, 跳过 23,905 次 (99.87% 准确率)
D1/D3 = 0 (99.87% 规避，31 次误读), 但 D5 DTLB +101%, D6 RefLat -33%
```

### 核心发现

1. **DONTNEED 陷阱 (D1/D3) 可被 root pagemap 完全规避** — `/proc/<pid>/pagemap` 是 root 权限下跨进程驻留查询的唯一手段 (bit 63=present, bit 62=swapped)，不触发目标缺页。`mincore()` 无法跨进程（仅限调用者自身地址空间）。但 pagemap 产生反向 PMU 异常 (D5+101%, D6-33%)

2. **Smart 模式 (root 最优) 无法消除 PMU 信号** — 只读热参考区驻留页, 完全跳过蜜罐。D1/D3=0。但 D4+44% (缓存一致性), D5+27% (TLB 失效), D6-32% (L1 预热) 仍可检测

3. **外部进程无法使用 mincore 预探测** — mincore() 只作用于调用者自身地址空间（防御者用它自检是合法的）。外部攻击者唯一跨进程预探测手段是 `/proc/<pid>/pagemap`（需 root）。攻击者始终以 root 权限运行

4. **PMU 信号方向编码攻击策略**:
   - Blind (外部): D5 +34% (GUP 缺页→TLB 失效)
   - Smart (外部): D5 +27% (GUP 无缺页但仍有 TLB 压力)
   - Pagemap (外部 root): D5 +101% (pagemap 页表遍历+驻留页 GUP)

5. **不存在完美隐身的跨进程内存扫描:**

| 攻击者能力 | 权限 | 规避 D1/D3 | 不可消除信号 | 检测难度 |
|------------|------|-----------|-------------|:---:|
| Blind | root | 0% | D1-D6 全维度 | 极低 |
| Smart (跳过陷阱区) | root | 100% | D4+44%, D5+27%, D6-32% | 中等 |
| Pagemap (逐页检查) | root | 99.87% | D5+101%, D6-33% | 中等 |
| Pagemap + 限速 | root | ~100% | PMU 信号减弱 | 高 |
| Pagemap + 限速 | root | ~100% | PMU 信号减弱 | 高 |

### 非陷阱页 (Resident Page) 检测

**实验:** 256 页 Target + 256 页 Reference, 全部驻留页, 永不 DONTNEED, 270+ 轮攻击。

| 指标 | Baseline | Attack | Δ |
|------|----------|--------|-----|
| Target P50 | 365-417ns | 365-417ns | 0ns |
| Signal rate | — | 2.2% (6/270) | 噪声级 |
| **Verdict** | | **NOT DETECTABLE** | |

**结论: 在 Linux 5.4 ARM64 上, process_vm_readv 读取纯驻留页不产生可测量的本地缓存/TLB 副作用。** 检测必须基于 DONTNEED 制造的状态差异。纯缓存污染检测在当前消费级 ARM64 SoC 上不可行。

### 五代实验 + 六维度 PMU 对分析结论的验证

本实验直接验证了 `vm_rw_detect_analysis.md` 中的关键论断:

| 分析结论 | 实验验证 |
|---------|---------|
| PerfEvent 跨通道可检测 (stat vs perf 差值) | D3 (MinFlt) = 外部 fault 精确 1:1 计数 |
| 时延检测需配合陷阱页 | D6 HonLat: 陷阱页 -90%, 非陷阱页 0% |
| ARM64 PMU task-context 隔离 (自身 PMU 不反映外部事件) | D4/D5 检测到的是**本核自身的副作用** (TLB 污染/缓存压力), 而非直接的外部事件 |
| pagemap 预探测可绕过 fault 类检测 | Pagemap 模式 D1/D3 = 0 (99.87% 规避) |
| 但残余 PMU 信号不可消除 | D5 +101%, D6 -33% |
| mincore 无跨进程能力 | 外部进程 mincore → ENOMEM；攻击者唯一跨进程手段是 `/proc/<pid>/pagemap`（root） |

| 文件 | 修改内容 |
|------|---------|
| `attacker.c` | +`#include <stdint.h>`; +`#include <fcntl.h>`; +`do_probe()` pagemap 探测命令 |
| `detect.h` | 独立 mincore_region → trap_indices[128]/trap_count/round; +MinFlt 字段; +PerfEvent 跨通道字段 (perf_fd, perf_clock_fd, prev_perf_*) |
| `detect.c` | 陷阱页散布于 ref_region; 修复 detect_swap/detect_mincore 先查后收; 陷阱轮换; +detect_minflt; +detect_perf (跨通道测序); +perf_event_open 封装; 移除旧 perf_event tracepoint 代码 |
| `detector.c` | CacheFlush 不触发自毁; 输出陷阱页数; 7→8 个检测方法 |
| `CMakeLists.txt` | 移除 `-llog` 链接 |

## 最终检测能力总结

| 攻击类型 | 用户态检测 (防御者非root) | 攻击者权限 | root 检测 |
|---------|-----------|:---:|---------|
| `process_vm_readv` 直接读 | **PerfEvent跨通道** + **时延检测** + **mincore** | root | **kprobes** |
| pagemap 预探测 + 批量读 resident | **陷阱轮换** (竞态窗口) | root | **kprobes** |
| 逐页 pagemap + readv (99.87% 规避陷阱) | **几乎无法检测** (31/23936 误读，仅 PMU 级残留) | root | **kprobes** |
| L3 + 使用窃取数据 (渲染/外泄) | **蜜罐令牌** (数据溯源) | root | **kprobes** |
| `process_vm_writev` (写) | **Canary** + **GuardPage** | root | **kprobes** |
| pagemap 侦察 (只读不写) | 无法检测 (无痕侧信道) | root | 无法检测 |

### 核心结论

1. **用户态可检测的四层攻击**（攻击者均为 root）:
   - L1 直接读: PerfEvent 跨通道、时延检测、mincore（防御者自检）均可检测
   - L2 预探测+批量读: 陷阱轮换制造竞态窗口 (窗口>周期时必命中)
   - L3 逐页 pagemap+readv: **用户态内存副作用检测的终点**——竞态窗口仅~17μs，11,000次读取才期望命中1次陷阱
   - L4 L3 + 使用窃取数据: **应用层蜜罐 (数据溯源)**——将检测从内存层提升到数据使用层，pagemap 无法区分合法数据与蜜罐数据

2. **时延检测是 PerfEvent 的有力补充**: 纯用户态 `clock_gettime` 计时，无需 `CONFIG_PERF_EVENTS`，无需 `perf_event_paranoid` 配置。驻留页/非驻留页时延差异 ~20-50x，信噪比充足。但必须配合陷阱页使用

3. **ARM64 硬件 PMU 方案不可行（经严格验证）**: 五个探索方向（系统级监控、LLCC-PMU、REMOTE_ACCESS、HW_CACHE、未知 PMU type）全部失败。根因: ARM PMU task-context 隔离 + SELinux 阻断系统级访问

4. **所有 fault 类检测的进化链**（攻击者始终 root，防御者非 root）:
   ```
   直接读 → pagemap预探测 → 陷阱轮换 → 逐页pagemap → syscall监控(需root)
     ✅         ✅           ✅(竞态)    ❌(用户态)     ✅(root)
                                            ↓
                                     数据使用 (渲染/外泄)
                                            ↓
                                 应用层蜜罐 ✅(数据溯源)
   ```

5. **用户态攻防终局**: 攻击者采用逐页 pagemap + readv 可将基于内存副作用的检测信号压缩至极低水平（99.87% 规避率，仅 0.13% 误读），但**不可完美消除**——六维度 PMU 实验中 31 次误读产生了 D5 DTLB +101%、D6 RefLat -33% 的 PMU 级残留信号。更重要的是，**检测可以在数据使用层继续进行**——将问题从"检测内存被读"转变为"检测数据被用"。`process_vm_readv` 通过 `FOLL_REMOTE` 不改变目标进程的 Referenced/I/O/swap，用户态检测本质上依赖"被动副作用"。蜜罐令牌通过将检测提升到应用层，利用攻击者必须"使用"数据才能获益的根本约束，打破了内存层的对称性僵局

6. **pagemap 的能力边界**: `/proc/<pid>/pagemap` 可以区分驻留页/非驻留页（帮助攻击者绕过陷阱页），但**不能区分合法数据/蜜罐数据**（两者都是驻留页中的字节）。这是防御方在应用层的不对称优势——攻击者的侦察工具在数据语义层完全失效。`mincore()` 仅用于防御者自检，攻击者无法用它跨进程探测。

## KPM 真实项目检测面分析

### 项目概述

分析了实际 KPM (Kernel Process Manipulation) 游戏外挂项目（`CPU菜单KPM`），其架构为：

```
内核层:  KPM 内核模块 → 拦截 prctl() syscall
            ↓ access_process_vm() / 物理内存直读 (page table walk)
用户态:  作弊进程 → DataThread() 循环读取游戏内存
            ↓ 解析坐标/血量/骨骼/队伍
            ↓ 填充 Aim[] 数组
            ↓ RenderThread() → CPU 纯渲染
            ↓ ANativeWindow_lock() 直接写入 surface buffer
            ↓ ANativeWindow_unlockAndPost()
屏幕:     ESP 方框/骨骼/名字/血条 overlay
```

关键差异：**纯 CPU 渲染（`ANativeWindow_lock` 直接写 buffer），不经过 GPU API（无 `eglSwapBuffers` / `vkQueuePresentKHR`），同权限应用层无法截取渲染输出。**

### 内存读取路径

```c
// kernel.h — 5 个自定义 prctl 命令码
#define PRCTL_MEM_READ      0x4D454D01  // access_process_vm 方式
#define PRCTL_MEM_WRITE     0x4D454D02
#define PRCTL_GET_PID       0x4D454D03
#define PRCTL_MEM_READ_SAFE 0x4D454D04  // 物理内存直读 (page table walk)
#define PRCTL_MEM_WRITE_SAFE 0x4D454D05

// 每次读内存 = prctl 调用
prctl(0x4D454D01, (unsigned long)&op, 0, 0, 0);
// op = { target_pid, addr, buffer, size }
```

**KPM 比 `process_vm_readv` 更隐蔽的原因**：

| 维度 | process_vm_readv | KPM prctl |
|------|:---:|:---:|
| **syscall 目标** | 直接针对游戏进程 PID | 针对作弊进程自身 |
| **audit 可见性** | syscall tracepoint 可捕获 | prctl 是合法通用 syscall |
| **目标进程 fault** | FOLL_REMOTE → 可能触发 min_flt | 物理直读模式完全不触发 |
| **/proc/pid/io** | 不变 | 不变 |
| **perf_event 计数** | 不变（task-context 隔离） | 不变 |

**SAFE 模式**（物理内存直读）：内核模块通过遍历目标进程页表获取物理地址，直接从物理内存读取，不经过 `access_process_vm` 的 FOLL_REMOTE 路径，**目标进程零可观测副作用。**

### 各层检测面

```
                        用户态可检测?  root 可检测?  实际方法
                        ────────────  ───────────   ────────
内核模块加载:             ❌            ✅ kprobe    hook init_module
prctl 读内存:             ❌            ✅ kprobe    hook __arm64_sys_prctl
游戏内存被读:             ❌            ❌           物理直读，完全无痕
渲染输出截取:             ❌            ✅ screencap CPU 渲染无 GPU API 可 hook

作弊进程存在:             ✅ /proc 扫描  ✅          遍历 cmdline/maps/fd
游戏内存被写 (自瞄):      ✅ Canary      ✅          游戏内校验 camera 角度
玩家行为异常:             ✅ 服务端      ✅          令牌嵌入 + 行为比对
```

### 四个有效检测点

#### 检测点 1：作弊进程存在性（用户态可行）

游戏进程定期扫描 `/proc`：

```
1. 窗口检测:
   → 非白名单 overlay 窗口存在 (如 "AKI")

2. 进程检测:
   → 陌生进程频繁读取 /proc/<game_pid>/maps (暴露在 inotify/fanotify)

3. fd 检测:
   → 异常 socket 连接 (T3 验证服务器)
   → 打开的 /proc/<game_pid>/mem (非自身进程)
```

#### 检测点 2：自瞄回写——游戏内校验（用户态可行）

```c
// 自瞄直接写游戏内存 (main.cpp:1197-1203)
driver->writeSafe<float>(cameraComponent + 0x184, angle.X);
driver->writeSafe<float>(cameraComponent + 0x188, angle.Y - RY);

// 子弹速度修改
driver->writeSafe<float>(...BULLETFIRESPEED, 100000000000);
```

游戏反作弊线程可校验：

```c
float expected = computeCameraFromInput(input_state);
float actual   = *(float*)(cameraComponent + 0x184);
if (fabs(expected - actual) > fov_threshold) {
    report_memory_tampering();  // 角度被外部修改
}
```

Canary 方案同样适用：在关键内存区域（`BULLETFIRESPEED`、camera 角度）嵌入校验值，定期比对。

#### 检测点 3：服务端令牌——行为比对（用户态不可行，需服务端配合）

这是最有效的方案。不需要截取渲染输出，服务端通过下发差异化数据给每个客户端，比对客户端行为。

**例 1：队伍 ID 作为天然令牌**

```c
// 作弊代码 (main.cpp:828)
if (myTeam == TeamID || TeamID == 0) continue;  // 过滤队友
```

服务端将同一个 bot 下发给不同客户端时分配不同 team：

```
客户端 A 视角: bot 在 team 3  → 作弊工具过滤掉（不显示）
客户端 B 视角: bot 在 team 7  → 作弊工具过滤掉（不显示）
```

如果 A 的作弊工具读取了 B 的内存（bot 在 team 7），或 A 的自瞄指向了它本应过滤的 bot——服务端通过击杀日志比对可发现 A "知道"了不该知道的信息。

**例 2：bot 名字嵌入令牌**

```
客户端 A: bot 名字 "Soldier_3A7F"  ← 3A7F = hash(secret_A, bot_id)
客户端 B: bot 名字 "Soldier_B9C2"  ← B9C2 = hash(secret_B, bot_id)
```

如果客户端 A 的行为日志中出现对 `Soldier_B9C2` 的交互，说明 A 读取了 B 的内存。不需要截屏。

**例 3：浮点数低位隐写**

护盾值、血量等 float 的低 16 位尾数可嵌入 token 而不影响游戏体验：

```
客户端 A 看到的 bot 护盾: 75.00391  (浮点表示 0x42960080)
客户端 B 看到的 bot 护盾: 75.00781  (浮点表示 0x42960100)
显示均为 75，但精确值不同 → 渲染的血条像素宽度有极微差异
```

#### 检测点 4：kprobes——root 终极方案

```bash
# 钩 prctl syscall，过滤 KPM 自定义命令码
echo 'p:kpm_read __arm64_sys_prctl cmd=%x0' > /sys/kernel/tracing/kprobe_events
# cmd == 0x4D454D01 或 0x4D454D04 → 检测到内存读取

# 钩 init_module，检测内核模块注入
echo 'p:kpm_load init_module mod=%x0' > /sys/kernel/tracing/kprobe_events
```

### 攻击进化链（完整版——含 KPM）

> **权限模型**：攻击者始终 root 权限，防御者非 root 用户权限。跨进程探测使用 `/proc/<pid>/pagemap`。

```
L0: process_vm_readv (用户态 syscall, root 权限)
    → 陷阱页 (min_flt) / 时延检测                             ✅ 用户态可检测

L1: pagemap 预探测 + process_vm_readv
    → 陷阱轮换 (竞态窗口 93%)                                  ✅ 用户态可检测

L2: 逐页 pagemap + process_vm_readv
    → 内存副作用几乎归零，仅 PMU 级残留 (D5+101%, D6-33%)    ⚠️ 几乎不可检测

L3: KPM 内核模块 (物理内存直读)
    → syscall 目标变为自身, 目标进程零副作用                     ❌ 比 L2 更隐蔽

L4: L2/L3 + 数据使用
    ├─ 渲染到 GPU (GPU API hook)                               ✅ 部分可检测
    ├─ 渲染到 CPU (ANativeWindow)                               ❌ 用户态不可截帧
    ├─ 自瞄回写 (内存完整性校验)                                ✅ 用户态可检测
    ├─ 服务端令牌 (行为比对)                                    ✅ 服务端可检测
    └─ 进程存在性 (/proc 扫描)                                  ✅ 用户态可检测
```

### 核心启示

1. **KPM 物理内存直读是内存检测的终极形态**：目标进程零可观测副作用，比 `process_vm_readv` + 逐页 pagemap 更隐蔽。所有基于内存层（缺页/PMU/时延）的用户态检测方案全部失效。

2. **CPU 纯渲染关闭了渲染截取这条检测路**：`ANativeWindow_lock` 直接写 buffer，无 GPU API 可 hook。同权限进程也无法读取其他进程的 surface buffer。

3. **但作弊工具的两条"使用"路径永远存在**：
   - **读后必渲染**（否则无意义）→ 检测面转移到服务端行为比对
   - **自瞄必回写**（否则无法生效）→ 检测面是游戏内内存完整性校验

4. **用户态客户端能做的**：进程存在性扫描 + Canary/内存完整性校验 + 关键字段校验（camera 角度、子弹速度等）

5. **检测重心应放在服务端**：服务端下发差异化数据（team/bot名字/浮点隐写），比对客户端上报的行为。这不需要截取渲染输出，利用的是"作弊工具必须使用数据产生可观测行为"这一根本约束
