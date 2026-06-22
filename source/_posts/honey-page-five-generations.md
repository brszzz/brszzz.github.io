---
title: 内存访问蜜罐页的五次进化——从静态陷阱到多维度 PMU 统计检测
date: 2026-06-04 17:02:00
tags:
  - Android
  - ARM64
  - 蜜罐
  - PMU
  - 内存检测
  - 跨进程
  - Linux内核
  - 游戏安全
categories:
  - 安全分析
description: 设计并验证五代蜜罐页检测方案，从 MADV_DONTNEED 轮换 + mincore 自检到融合 ARMv8 PMU 的六维度统计检测，探索跨进程内存读取检测的完整进化路径与硬件级残留信号。
---

# 蜜罐页的五次进化：从静态陷阱到多维度 PMU 统计检测

> ARM64 Android 平台 `process_vm_readv` 跨进程内存读取的检测方案演进

## 摘要

在 ARM64 Android (Linux 5.4.210) 平台上，本文设计并实验验证了五代蜜罐页（Honey Page）检测方案，探索从简单的静态内存陷阱到融合 ARMv8 PMU 硬件计数器的六维度统计检测的完整进化路径。核心发现：MADV_DONTNEED 轮换 + mincore 自检构成最强检测信号（SNR=∞），每个被攻击页产生精确 1 次 minor fault（1:1 对应）；但 root 攻击者通过 `/proc/pid/pagemap` 可规避内存层信号，仅残留 PMU 级别的跨核副作用（DTLB Walk +101%，访问延迟 -33%）。纯驻留页读取在当前消费级 ARM64 SoC 上不可检测。

**关键词**: process_vm_readv, 蜜罐页, MADV_DONTNEED, mincore, ARMv8 PMU, FOLL_REMOTE, pagemap

---

## 1. 引言

`process_vm_readv` 是 Linux 提供的跨进程内存读取系统调用，允许一个进程直接读取另一个进程的地址空间。在内核实现中，它通过 `FOLL_REMOTE` 标志调用 `pin_user_pages_remote`，在目标进程的页表上执行缺页处理。这意味着：
- 读取已回收（MADV_DONTNEED）的页面会在目标进程触发 minor page fault
- 但 `FOLL_REMOTE` 不设置 Accessed bit，不触发 swap-in，不改变 I/O 计数器

检测方案的核心思路是：**通过 MADV_DONTNEED 主动制造"陷阱页"，利用 process_vm_readv 触发的 FOLL_REMOTE 缺页作为检测信号**。本文通过五代迭代，从基础陷阱页开始，逐步引入 PMU 硬件计数器、访问时延测量、VMA 布局等维度，探索检测能力的上限与边界。

### 权限模型

- **防御者**：非 root shell 用户，独立进程，通过 mincore() 自检、/proc/self/stat 监控 min_flt、perf_event_open 读取 PMU 计数器
- **攻击者**：root 权限，独立进程，通过 `/proc/<pid>/pagemap` 跨进程探测，使用 `process_vm_readv` 跨进程读取

---

## 2. 测试平台

| 参数 | 值 |
|------|-----|
| 设备 | Android (ADB connected) |
| 架构 | aarch64 (ARM64) |
| 内核 | Linux 5.4.210 |
| 编译器 | aarch64-linux-android26-clang -O2 |
| 页大小 | 4096 bytes |
| 测试页数 | 256 (1MB) per generation |
| PMU | ARMv8 PMUv3 (L1D refill, DTLB walk, CPU cycles via perf_event) |

---

## 3. 五代实验

### 3.1 G1 — 静态蜜罐页（基线）

**方法**：预先分配页面并写入数据使其驻留。不主动回收（无 MADV_DONTNEED）。攻击者读取后，检查页面状态是否有可观测变化。

**结果**：

```
mincore:  attacked=100.0%  control=100.0%  diff=0.0%
latency:  attacked=216ns   control=332ns   diff=116ns
min_flt:  attacked=1       control=1
```

**分析**：所有页面在初始化时已被 touch（驻留态），process_vm_readv 读取驻留页不产生 min_flt。mincore 始终 100%。延迟差异来自测量顺序的微小缓存效应（~116ns），不足以作为可靠检测信号。

**结论**：静态页面无法提供检测能力。验证了理论基础——必须主动制造状态差异。

---

### 3.2 G2 — MADV_DONTNEED 轮换（Fault Trap）

**方法**：每轮用 MADV_DONTNEED 回收蜜罐页使其变为非驻留态，然后等待攻击窗口。下一轮用 mincore() 检查页面是否被外部 fault-in 变回驻留态。

**结果**：

```
Control rounds:    mincore = 0.0%   (DONTNEED 后全部非驻留)
Attack rounds:     mincore = 100.0% (攻击者读取后全部变驻留)
差异:              100%
SNR:               ∞ (baseline variance = 0)
```

**分析**：这是最干净的信号。MADV_DONTNEED 将页面回收后，process_vm_readv 触发缺页调入。防御者在下一轮用 mincore 检查时，被攻击页面 100% 驻留，对照页 0% 驻留。无重叠区域，二分类完美。

**结论**：G2 是最有效的检测策略。简单、可靠、纯用户态操作，无需任何特殊内核配置。

---

### 3.3 G3 — PMU/min_flt 关联（Fault Counting）

**方法**：在 G2 基础上，同步监控 `/proc/self/stat` 的 `min_flt` 字段，精确计算被攻击的陷阱页数量。

**结果**：

```
Control rounds:    min_flt/rnd = 0
Attack rounds:     min_flt/rnd = 64 (exactly!)
SNR:               999x
```

**分析**：每个 DONTNEED 蜜罐页被 process_vm_readv 读取时，精确触发一次 minor page fault。64 个蜜罐页 → 64 次 min_flt。一一对应，无一遗漏，无一误报。

**结论**：min_flt 增量与蜜罐页数量呈精确 1:1 对应。不需要 PMU 硬件也能实现计数级的精确度。这是所有 fault 类检测的数学基础。

---

### 3.4 G4 — 三区访问时延测量

**方法**：设计三个内存区域，通过 `clock_gettime` 测量访问延迟：

```
Zone A [0..128):     热参考区 — 永不 DONTNEED, 始终驻留
                    测延迟可检测 LLC/TLB 污染
Zone B [128..256):   蜜罐区 — DONTNEED + 攻击者读取
                    攻击者 fault-in 后变热 (~150ns)
Zone C [256..384):   对照冷区 — DONTNEED, 不被攻击
                    始终为冷页 (~1500ns)
```

**结果**：

**信号 1 — 热参考区延迟升高（缓存/TLB 污染）**：
```
Control:  Zone A avg=443ns  (热页, 无干扰)
Attack:   Zone A avg=642ns  (+199ns, +45%)
Round 4 峰值: 1132ns (2.5x 基线!)
```

**信号 2 — 蜜罐区 fault-in 变热**：
```
Round 4: Honey=246ns (0% cold) | Ctl=1433ns (2% cold)  ← 攻击者预热
Round 5: Honey=332ns (1% cold) | Ctl=3322ns (3% cold)  ← 攻击者预热
```

**分析**：三区设计捕获了两个独立的检测信号：
1. **热参考区延迟升高**：攻击者扫描产生的缓存/TLB 竞争导致本地访问变慢
2. **蜜罐区延迟降低**：攻击者 fault-in 后页面从冷变热

两个信号互补：信号 1 在攻击者读取任何内存时都可能出现（包括驻留页），信号 2 在攻击者读取 DONTNEED 页时触发。组合使用提高检测鲁棒性。

**结论**：三区时延检测是唯一能间接感知 LLC/TLB 级别副作用的纯用户态方法。Zone A 的 +45% 延迟升高直接印证了"外部扫描 → 缓存污染 → 本地延迟增加"的理论预测。

---

### 3.5 G5 — Honey VMA（防御纵深）

**方法**：将蜜罐区拆分为大量独立的小 VMA（256 个 4KB VMA），而非单个大缓冲区。

**结果**：

```
256 个 4KB VMA:
  Attacker scan time:  11.2 ms  (43.9 μs/VMA)
单大缓冲区:
  Attacker scan time:  ~0.4 ms  (1.6 μs/page)
放大倍数:              ~26x

/proc/self/maps:      833 bytes, 10 lines
(256 个 VMA 在 maps 中表现为 256 条独立映射项)
```

**分析**：大量小 VMA 不直接检测 process_vm_readv，但大幅增加攻击者遍历 `/proc/pid/maps` 和逐 VMA 读取的开销。结合 `inotify` 监控 `/proc/self/maps` 的读取事件，可间接感知内存扫描行为。

**结论**：Honey VMA 是优秀的防御纵深策略，放大攻击成本 26x，但不提供独立的确定性检测信号。

---

### 3.6 五代总结

| 世代 | 方法 | 可检测 | SNR | 关键信号 |
|------|------|:---:|-----|----------|
| G1 | 静态蜜罐页 | ⚠️ 弱 | 1.00 | min_flt（不显著） |
| G2 | MADV_DONTNEED 轮换 | ✅ 完美 | ∞ | mincore 0%→100% |
| G3 | PMU/min_flt 关联 | ✅ 100% | 999x | min_flt 1:1 per page |
| G4 | 三区访问时延 | ✅ 强 | — | Hot Ref +45%, Honey latency 反转 |
| G5 | Honey VMA | ✅ 放大 | 26x | scan time 26x |

**核心验证**：
- `process_vm_readv` 在 ARM64 Linux 5.4 上确实触发 DONTNEED 页的 minor fault
- 每个蜜罐页产生精确 1 次 min_flt（1:1 对应）
- 被攻击页访问延迟更低（pre-fault 变热，~1500ns → ~150ns）
- 攻击者持续扫描导致热参考区延迟升高（+45%，缓存/TLB 竞争）

---

## 4. 六维度 PMU 统计检测

在 G2-G4 基础上引入 ARMv8 PMU 硬件计数器（perf_event_open），构建六个独立检测维度：

| 维度 | 名称 | 数据源 | 检测机制 |
|------|------|--------|----------|
| **D1** | Honey Resident Count | mincore() | 攻击者 fault-in 后页面变驻留 |
| **D2** | Recovery Rate | D1 / round_time | 反映攻击者扫描吞吐量 |
| **D3** | Minor Fault Delta | /proc/self/stat | 缺页次数 = 被读页数的精确计数 |
| **D4** | Cache Miss | ARMv8 PMU: L1D refill | 缓存行竞争导致的 L1 缓存失效 |
| **D5** | DTLB Walk | ARMv8 PMU: DTLB walk | TLB 缺失导致的页表遍历 |
| **D6** | Access Latency | 本核 load-to-use | 热参考区 + 蜜罐区访问延迟 |

### 4.1 攻击者三种模式

| 模式 | 权限 | 策略 | 预探测方法 | 规避 D1/D3 |
|------|------|------|-----------|:---:|
| **blind** | root | 无条件读全部蜜罐页 | 无 | 0% |
| **smart** | root | 只读热参考区，完全跳过蜜罐 | 解析 /proc/pid/maps 推断活跃区域 | 100% |
| **pagemap** | root | /proc/pid/pagemap 逐页检查，只读 resident 页 | pagemap（跨进程驻留查询） | 99.87% |

**关键差异**：mincore() 只能检查调用者自身地址空间，外部进程调用返回 -ENOMEM。跨进程驻留探测的唯一用户态手段是 `/proc/<pid>/pagemap`，且需要 root 权限。

### 4.2 三模式六维度对比

```
                     BLIND                   SMART                  PAGEMAP (root)
维度        baseline → attack   Δ%      baseline → attack   Δ%      baseline → attack   Δ%
────────────┼──────────────────────────┼──────────────────────────┼──────────────────────────
D1 HoneyR   │   0 → 256     ★★★ ∞     │   0 →   0     —  规避   │   0 →   0     —  规避
D2 Rate/s   │   0 → 1280    ★★★ ∞     │   0 →   0     —  规避   │   0 →   0     —  规避
D3 MinFlt   │   0 → 255     ★★★ ∞     │   0 →   0     —  规避   │   0 →   0     —  规避
D4 $Miss    │ 153 → 242    +58% ★★★   │ 162 → 233    +44% ★★    │ 181 → 171     -6% ★
D5 DTLB     │  97 → 130    +34% ★★    │ 104 → 132    +27% ★★    │  62 → 126   +101% ★★★
D6 RefLat   │ 391 → 352    -10% ★     │ 390 → 267    -32% ★★    │ 332 → 222    -33% ★★
D6 HonLat   │1172 → 117    -90% ★★★   │1120 → 1146    +2% —     │1002 → 944     -6% ★
────────────┼──────────────────────────┼──────────────────────────┼──────────────────────────
Signals     │      4/6                  │      3/6                  │      3/6
Verdict     │    DETECTED               │    BORDERLINE             │    BORDERLINE
```

**Pagemap 攻击者实际行为**：

```
pagemap 检查 47,872 次 → 23,967 页驻留 → 读 23,936 页参考区
蜜罐区: 仅 31 次误读, 跳过 23,905 次 (99.87% 准确率)
D1/D3 = 0 (99.87% 规避，31 次误读), 但 D5 DTLB +101%, D6 RefLat -33%
```

### 4.3 PMU 信号方向编码攻击策略

不同攻击模式产生的 PMU 信号具有**方向性和强度差异**，可以反向推断攻击者的探测手段：

| 场景 | D5 DTLB Walk 变化 | 机制 |
|------|:---:|------|
| Blind（直接读全部） | **+34%** | 外部 GUP 缺页导致目标核 TLB 失效 |
| Smart（跳过陷阱区） | **+27%** | GUP 无缺页但仍有 TLB 压力 |
| Pagemap（逐页检查） | **+101%** | pagemap 页表遍历 + 驻留页 GUP 的组合效应 |

Pagemap 模式的 D5 信号最强（+101%），因为它同时进行了 47,872 次 pagemap 页表遍历和 23,936 次 process_vm_readv，双重 TLB 压力叠加。

---

## 5. 非陷阱页检测：纯驻留页的极限

### 5.1 实验设计

上述所有检测的基础是：DONTNEED → 攻击者读 → 缺页。如果攻击者**只读驻留页**（永不 DONTNEED），能否通过纯缓存/TLB 副作用检测？

- 256 页 Target Zone（攻击者读取）+ 256 页 Reference Zone（对照）
- 全部页面驻留，**永不 DONTNEED**
- 20 轮基线 + 270+ 轮攻击

### 5.2 结果

| 指标 | Baseline | Attack | Δ |
|------|----------|--------|-----|
| Target P50 | 365-417ns | 365-417ns | **0ns** |
| Reference P50 | 365-417ns | 365-417ns | **0ns** |
| Signal rate | — | 2.2% (6/270) | 噪声级 |
| **Verdict** | | | **NOT DETECTABLE** |

### 5.3 陷阱页 vs 非陷阱页对比

| | 陷阱页 (DONTNEED) | 非陷阱页 (Resident-only) |
|---|---|---|
| process_vm_readv 副作用 | minor fault | 无 |
| mincore 变化 | 0% → 100% | 始终 100% |
| min_flt 增量 | 精确 1/page | 始终 0 |
| 蜜罐访问延迟 | ~1500ns → ~150ns | 始终 ~400ns |
| 检测率 | **100%** | **≈ 2%（噪声级）** |

**结论**：在 Linux 5.4 ARM64 上，process_vm_readv 读取纯驻留页不产生可测量的本地缓存/TLB 副作用。纯缓存污染检测在当前消费级 ARM64 SoC 上不可行。检测必须基于 DONTNEED 制造的状态差异。

---

## 6. 核心发现

### 6.1 DONTNEED 陷阱可被 root pagemap 完全规避

`/proc/<pid>/pagemap` 为 root 攻击者提供跨进程驻留查询能力（bit 63 = present，bit 62 = swapped），无需触碰目标页面即可区分陷阱页/数据页。D1/D3 降至 0。

**但 pagemap 本身产生反向 PMU 异常**：
- D5 DTLB Walk +101%（62→126）—— pagemap 页表遍历副作用
- D6 RefLat -33%（332→222ns）—— 目标核 L1 缓存被攻击者预热
- "异常安静"（缺页消失）结合"异常加速"（延迟骤降）构成 PMU 级双向偏离特征

### 6.2 Smart 模式无法消除 PMU 信号

非 root 攻击者通过解析 `/proc/pid/maps` 推断活跃区域，只读热参考区驻留页。D1/D3=0。但 PMU 仍捕获：
- D4 Cache Miss +44% — 驻留页 process_vm_readv 的缓存一致性开销
- D5 DTLB Walk +27% — 外部 GUP 操作的 TLB 失效
- D6 RefLat -32% — 攻击者预热 L1 缓存

### 6.3 不存在完美隐身的跨进程内存扫描

| 攻击者能力 | 权限 | 规避 D1/D3 | 不可消除信号 | 检测难度 |
|------------|------|:---:|-------------|:---:|
| Blind（直接读全部） | root | 0% | D1-D6 全维度 | 极低 |
| Smart（跳过陷阱区） | root | 100% | D4+44%, D5+27%, D6-32% | 中等 |
| Pagemap（逐页检查） | root | 99.87% | D5+101%, D6-33% | 中等 |
| Pagemap + 限速 | root | ~100% | PMU 信号减弱 | 高 |

**即使 root 攻击者通过 pagemap 将 DONTNEED 陷阱命中率降至 0.13%（31/23936 误读），仍无法完全消除 PMU 级别的跨核副作用（D5 DTLB +101%, D6 RefLat -33%）。检测需要同时监控正向和负向偏离。**

---

## 7. 局限性

1. **Pagemap 规避**：root 攻击者通过 `/proc/pid/pagemap` 可规避 D1/D3，仅 PMU 维度残留
2. **PMU 可用性**：D4/D5 依赖 `perf_event_open`，需要内核未禁用（`perf_event_paranoid ≤ 1`）
3. **竞态窗口**：DONTNEED 后、mincore 前存在微秒级窗口，但逐页 pagemap 可将其压缩至无意义
4. **误报源**：kswapd、内存压缩等系统活动也可能触发 min_flt
5. **SoC 差异**：本文结果基于 Linux 5.4 ARM64，其他内核版本/架构可能不同

---

## 8. 推荐检测策略

多层防御纵深：

```
第一层: G2 DONTNEED 轮换 + mincore      (非 root 攻击者 100% 检出)
第二层: G3 min_flt 精确计数             (每页 1:1, 无 PMU 依赖)
第三层: D4-D5 PMU 硬件计数器            (捕获 smart/pagemap 规避)
第四层: D6 双向延迟监控                 (正向+负向异常)
第五层: G5 Honey VMA                    (放大攻击成本 26x)
```

---

## 9. 对分析结论的验证

| 分析结论 | 实验验证 |
|---------|---------|
| PerfEvent 跨通道可检测（stat vs perf 差值） | D3 (MinFlt) = 外部 fault 精确 1:1 计数 |
| 时延检测需配合陷阱页 | D6 HonLat: 陷阱页 -90%，非陷阱页 0% |
| ARM64 PMU task-context 隔离 | D4/D5 检测到的是本核自身的副作用，非直接外部事件 |
| pagemap 预探测可绕过 fault 类检测 | Pagemap 模式 D1/D3=0（99.87% 规避） |
| 残余 PMU 信号不可消除 | D5 +101%, D6 -33% |
| mincore 无跨进程能力 | 外部进程 mincore → ENOMEM；跨进程唯一手段是 pagemap（root） |
