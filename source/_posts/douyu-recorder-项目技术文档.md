---
title: 斗鱼直播录制与分析系统 — 项目技术文档
date: 2026-05-25 10:30:00
tags:
  - 斗鱼
  - 直播录制
  - AI分析
  - Python
  - 弹幕协议
  - 逆向工程
  - FFmpeg
  - Whisper
  - DeepSeek
  - 协议分析
categories:
  - 直播技术
description: 完整的斗鱼直播录制与AI分析系统技术文档，涵盖弹幕协议逆向、视频流签名、Whisper语音转写、AI高光识别等核心技术实现
---

## 一、项目简介

本项目是一个完整的斗鱼直播录制与 AI 分析系统，包含两大模块：

- **douyu-recorder**：CLI 工具，用于录制斗鱼直播间的视频流和弹幕（danmaku），支持 WebSocket/TCP 双通道弹幕采集、FFmpeg 视频录制、多清晰度选择。
- **analyzer**：AI 分析工具，对录制的直播回放进行语音转写、弹幕密度分析、视频帧采样，并通过大模型（DeepSeek / Claude）自动识别高光时刻，生成切片报告。

项目采用纯 Python 实现，配合 Node.js 子进程处理斗鱼的 JS 签名算法。

---

## 二、项目结构

```
AI-Split-live-record/
├── douyu_recorder/           # 录制模块
│   ├── cli.py                # Click CLI 入口
│   ├── recorder.py           # 主协调器（视频+弹幕并发调度）
│   ├── danmaku.py            # 弹幕客户端（WebSocket 优先，TCP 兜底）
│   ├── protocol.py           # STT 二进制协议编解码
│   ├── sign.py               # 流地址签名获取（移动端 + PC 端 API）
│   ├── stream.py             # FFmpeg 视频流录制
│   ├── utils.py              # 工具函数（日志、路径、房间号解析）
│   ├── get_h5play.js         # PC 端 API 签名（Node.js）
│   └── web-encrypt.js        # 斗鱼官方 web-encrypt JS（本地副本）
├── analyzer/                 # AI 分析模块
│   ├── cli.py                # Click CLI 入口
│   ├── danmaku_loader.py     # 弹幕加载、密度计算、峰值检测
│   ├── video_audio.py        # 音频提取、Whisper 转写、视频帧提取
│   ├── highlight.py          # AI 高光分析（DeepSeek API / Claude CLI）
│   ├── exporter.py           # 结果导出（JSON / Markdown）
│   └── signals.py            # 信号处理
├── tests/
│   └── test_protocol.py      # 协议层单元测试
└── pyproject.toml
```

---

## 三、弹幕系统 — 技术实现细节

### 3.1 STT 二进制协议

斗鱼弹幕使用自定义的 STT（Simple Text Transport）二进制协议。每条消息的编码格式为：

```
key1@=value1/key2@=value2/ ... \0
```

- `@=` 分隔键和值
- `/` 分隔字段对
- `\0` 结束符
- 特殊字符转义：`@` → `@S`，`/` → `@A`

### 3.2 二进制帧结构（12 字节头）

在实际传输中，STT 文本被封装在二进制帧中：

| 偏移 | 大小 | 类型 | 字段 |
|------|------|------|------|
| 0 | 4 | int32 | msg_len = body_len + 8 (小端序) |
| 4 | 4 | int32 | msg_len 重复（冗余校验） |
| 8 | 2 | int16 | msg_type (689=客户端→服务器, 690=服务器→客户端) |
| 10 | 1 | uint8 | 加密标志 (0=无加密) |
| 11 | 1 | uint8 | 保留位 (0) |
| 12 | N | bytes | STT 编码的 UTF-8 正文，\0 结尾 |

完整帧 = 12 字节头 + body_len 字节正文。

### 3.3 连接流程

弹幕客户端采用 **WebSocket 优先，TCP 兜底** 的策略：

**WebSocket 路径**（主路径）：

1. 使用 `aiohttp` 连接到 `wss://danmuproxy.douyu.com:8501~8506`
2. SSL 需特殊配置：关闭证书验证，设 `ciphers="DEFAULT:@SECLEVEL=1"` 以兼容斗鱼的旧版 TLS
3. 连接成功后立即发送 `loginreq`（登录请求）+ `joingroup`（加入房间分组）
4. 启动 45 秒间隔的心跳（发送 `mrkl` 消息）
5. 在主循环中读取二进制消息，解析并过滤弹幕类型

**TCP 路径**（兜底）：

1. 连接到 `danmu.douyu.com:8601/8602`
2. 发送相同的 `loginreq` + `joingroup`
3. TCP 服务器返回的数据可能包含多个拼接的帧，需要循环解析

### 3.4 握手流程的关键细节

通过逆向 npm 包 `@faintout/douyudm` 确认的正确握手流程：

```
客户端 ──loginreq──▶ 服务器
客户端 ──joingroup─▶ 服务器    ← 两条消息连续发送，不等待响应
客户端 ◀─loginres── 服务器
客户端 ◀─pingreq─── 服务器     ← 服务器主动 ping
客户端 ──pingres──▶ 服务器     ← 立即回复
客户端 ──mrkl─────▶ 服务器     ← 每 45 秒心跳
```

错误做法：在 loginreq 和 joingroup 之间等待或插入 mrkl——这会导致服务器不将客户端加入房间分组。

---

## 四、视频流获取 — 技术实现细节

### 4.1 签名机制

斗鱼的真实流地址不能直接从页面获取，需要通过 JS 签名算法调用内部 API。

**移动端 API（旧方案）**：

1. 请求 `https://m.douyu.com/{room_id}` 获取页面 HTML
2. 从 HTML 中提取 `ub98484234` 函数（混淆后的 JS 签名代码）
3. 通过 Node.js 子进程执行该 JS，传入 `(room_id, did, timestamp)` 参数
4. Node.js 脚本提供 `CryptoJS.MD5` shim（使用 Node 原生 crypto 模块）
5. 获取签名参数后，POST 到 `https://m.douyu.com/api/room/ratestream`
6. 解析返回的 HLS/FLV 流地址

**PC 端 API（当前方案，推荐）**：

1. 加载斗鱼官方的 `web-encrypt.js`（Webpack 打包的加密模块）
2. 在 Node.js 中提供完整的浏览器环境 shim（`window`、`document`、`crypto.subtle`、`fetch`、`localStorage` 等）
3. 调用 `getLegacyFirstStream()` 获取签名后的流地址
4. PC API 返回 `multirates` 数组，包含所有可用清晰度（原画1080P60、超清、高清等）
5. 原画质量通过将默认 rate 从 -1 改为 0 实现

### 4.2 FFmpeg 录制

- 使用 `ffmpeg -c copy` 直接复制流，避免重新编码
- HTTPS CDN URL 需加 `-tls_verify 0` 跳过证书验证
- 异步读取 `stderr` 防止缓冲区死锁
- 每 3 分钟自动刷新流地址（斗鱼流地址有时效性）

---

## 五、关键 Bug 与修复

### 5.1 致命 Bug：4 字节偏移导致弹幕完全失效

**现象**：弹幕连接正常（loginres、pingreq 均正常收发），但始终收不到任何聊天消息（chatmsg、dgb 等），连续数小时接收量为 0。

**根因**：`protocol.py` 的 `encode()` 函数中，帧头的 `msg_len` 字段填入了错误的值：

```python
# 错误（修复前）：
total_len = HEADER_LEN + len(body)   # = 12 + body_len
msg_len = total_len                   # 比正确值多 4！

# 正确（修复后）：
msg_len = len(body) + 8               # 匹配 npm packet.js 的 Encode 逻辑
```

**影响链**：服务器读取帧头中的 `msg_len=body_len+12`，期望收到 `body_len+12` 字节，但实际发送的 `msg_len` 导致服务器解析下一帧时偏移 4 字节，`joingroup` 命令被错误解析，"加入房间分组"操作实际从未成功执行。

### 5.2 其他关键修复

- **decode() 正文截断偏移错误**：`body_end` 计算偏差修正
- **decode_tcp_response 误过滤消息类型**：移除 msg_type 过滤
- **Node.js console 递归调用**：改用 `process.stderr.write.bind(process.stderr)`

---

## 六、AI 分析系统

### 6.1 处理流程

```
 录制文件 (FLV + JSONL)
        │
        ├──▶ FFmpeg 提取音频 (16kHz WAV)
        │         └──▶ faster-whisper 语音转文字
        │
        ├──▶ FFmpeg 提取视频帧 (每 30~60 秒一张)
        │         └──▶ Base64 编码 → AI 视觉分析
        │
        ├──▶ 弹幕 JSONL 加载
        │         └──▶ 时间归一化 → 滑动窗口密度计算 → 峰值检测
        │
        └──▶ AI 综合分析
                  │
        ┌────────┴────────┐
        │  DeepSeek API    │  Claude Code CLI
        └────────┬────────┘
                  │
                  ▼
        高光时刻列表 + 总结 + 标签
```

### 6.2 弹幕密度分析

- 使用滑动窗口（默认 30 秒窗口，15 秒步长）计算弹幕密度
- 通过标准差阈值（2σ）识别密度峰值
- 提取 2 字符短语作为热词

### 6.3 AI 高光识别

- 将视频按 3 分钟分块，每块独立分析
- System Prompt 定义了 10 种高光分类
- 评分标准 0-10 分
- 支持两种 AI 后端：DeepSeek API（OpenAI 兼容）+ Claude Code CLI

---

## 七、依赖技术栈

| 组件 | 技术 | 用途 |
|------|------|------|
| 弹幕协议 | 自定义 STT 二进制协议 | 编解码斗鱼弹幕帧 |
| 弹幕传输 | WebSocket (aiohttp) + TCP fallback | 实时接收弹幕 |
| 视频录制 | FFmpeg subprocess | 下载和保存 FLV 流 |
| JS 签名 | Node.js 子进程 | 执行斗鱼 web-encrypt 签名 |
| 语音转写 | faster-whisper (base 模型) | 直播语音转文字 |
| AI 分析 | DeepSeek API / Claude Code CLI | 高光时刻识别 |
| CLI 框架 | Click | 命令行参数解析 |
| 日志 | Loguru | 结构化日志 |

---

## 八、总结

本项目实现了斗鱼直播的完整录制与分析流程。技术难点主要集中在三个方面：

1. **弹幕协议逆向**：斗鱼没有公开的弹幕协议文档，需要通过抓包和对比 npm 开源实现来理解二进制帧格式。
2. **视频签名绕过**：斗鱼使用混淆的 JavaScript 进行流地址签名，需要在 Node.js 中搭建完整的浏览器环境 shim。
3. **AI 分析质量**：如何让大模型输出准确的时间戳、将时间边界对齐到语音段落、处理重叠和冲突的片段，需要多层后处理逻辑。
