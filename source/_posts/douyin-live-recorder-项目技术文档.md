---
title: 抖音直播录制工具 — 项目技术文档
date: 2026-05-25 10:35:00
tags:
  - 抖音
  - 直播录制
  - Python
  - 弹幕采集
  - Protobuf
  - FFmpeg
  - WebSocket
  - 逆向工程
  - asyncio
  - 自动化
categories:
  - 直播技术
description: Python CLI 抖音直播录制工具，支持高清视频原画下载和时间同步弹幕采集，含完整技术架构与逆向实现细节
---

## 项目概述

一个 Python CLI 工具，用于录制抖音（Douyin）直播流，支持**高清视频原画下载**和**时间同步弹幕采集**。视频通过 ffmpeg 以 `-c copy` 零损耗下载 FLV 流，弹幕通过 WebSocket 实时捕获聊天消息，使用单调时钟锚点实现视频与弹幕的时间对齐。

- **语言**: Python 3.10+
- **许可**: 内部使用
- **版本**: 0.1.0

---

## 使用方法

### 安装

```bash
pip install -e .
```

### 系统依赖

| 依赖 | 用途 | 安装方式 |
|------|------|----------|
| ffmpeg | 视频流下载 | `winget install ffmpeg` / `brew install ffmpeg` |
| Node.js | WebSocket 签名生成 (可选) | `winget install nodejs` |

### 命令行

```bash
# 基本用法 — 录制直播（视频 + 弹幕）
douyin-live-recorder https://live.douyin.com/123456789

# 指定输出目录
douyin-live-recorder https://live.douyin.com/123456789 -o ./my_recordings

# 仅录制弹幕（跳过视频）
douyin-live-recorder https://live.douyin.com/123456789 --only-danmaku

# 仅录制视频（跳过弹幕）
douyin-live-recorder https://live.douyin.com/123456789 --only-video

# 定时录制（60秒后自动停止）
douyin-live-recorder https://live.douyin.com/123456789 --timeout 60

# 使用 Cookie（某些直播间需要登录）
douyin-live-recorder https://live.douyin.com/123456789 --cookie "ttwid=xxx; sessionid=xxx"

# 浏览器登录获取 Cookie
douyin-live-recorder --login --phone 13812345678

# 视频质量选择
douyin-live-recorder https://live.douyin.com/123456789 -q hd    # 高清
douyin-live-recorder https://live.douyin.com/123456789 -q sd    # 标清
douyin-live-recorder https://live.douyin.com/123456789 -q original  # 原画（默认）

# 输出格式
douyin-live-recorder https://live.douyin.com/123456789 -f mp4   # MP4（自动 remux）

# 自动监听模式 — 监听直播间，开播后自动录制
douyin-live-recorder --auto

# 指定配置文件
douyin-live-recorder --auto --config my_rooms.json
```

### 自动监听模式

`--auto` 模式通过 JSON 配置文件持续监听多个直播间，检测到开播后自动启动录制，直播结束后自动回到监听状态。

**工作流程**:
1. 读取配置文件中所有房间
2. 每隔 N 秒循环检查每个房间是否开播
3. 检测到开播 → 后台启动 Recorder（视频 + 弹幕双录）
4. 直播结束 → 自动 finalize 文件，该房间恢复监听
5. 支持多房间同时录制（各自独立 asyncio Task）
6. Ctrl+C → 优雅停止所有录制并退出

---

## 项目架构

### 数据流

```
直播URL
  │
  ▼
[stream_url.py]  ──► VideoStreamInfo (room_id, anchor_name, stream_urls, cookies)
  │
  ├─ HTML 页面解析 (正则提取 flv_pull_url)
  └─ API 回退 (/webcast/room/web/enter/)
  │
  ▼
[recorder.py]  Orchestrator
  │
  ├──► [video_recorder.py]  ffmpeg -c copy → .flv 文件
  │
  └──► [danmaku/websocket_client.py]  WSS 连接
         │
         ▼
       [danmaku/parser.py]  手动 Protobuf 解析
         │
         ▼
       [output.py]  按行写入 JSON → finalize 格式化
```

### 核心设计

#### 1. 双协程并发架构

`Recorder.run()` 创建两个独立的 asyncio 任务：

| 任务 | 类 | 说明 |
|------|-----|------|
| 视频录制 | `VideoRecorder` | ffmpeg 子进程下载 FLV 流，`-c copy` 无重编码 |
| 弹幕采集 | `DanmakuClient` | WebSocket 接收二进制帧，解析 Protobuf 消息 |

#### 2. 时间同步机制

- **单调时钟** (`time.monotonic()`) — 不受系统时间调整影响，用于弹幕 offset_ms
- **本地时间** (`datetime.now()`) — 用于输出目录/文件名、wall_start 元数据

#### 3. 流地址提取 — 两层策略

1. **HTML 正则解析**（优先） — 直接从直播页面 `<script>` 标签中提取 `flv_pull_url`
2. **API 回退** — 调用 `/webcast/room/web/enter/` API，携带 X-Bogus 签名

支持的画质: `FULL_HD1` (原画), `HD1` (高清), `SD1`/`SD2` (标清)

#### 4. 弹幕 WebSocket 协议

```
WebSocket 二进制帧
  → PushFrame (protobuf)
    → field 8: gzip 压缩的 Response
      → Response.message (repeated)
        → Message { method, payload }
          → ChatMessage / GiftMessage / LikeMessage / MemberMessage / ...
```

**心跳机制**:
- WebSocket 层: `ping_interval=10s`（库级别 ping/pong）
- 应用层: 每 10 秒发送 `PushFrame{payloadType='hb'}`（业务心跳）
- 收到数据帧后发送 `PushFrame{payloadType='ack', logId=...}`（ACK 确认）

**重连策略**:
- 异常关闭 → 指数退避重连（1s → 2s → 4s → ... → 30s 封顶）
- 正常关闭（code 1000/1001/1005）→ 判定为直播结束，停止重连

#### 5. 手动 Protobuf 解析器

**不需要 `.proto` 编译**，纯 Python 实现 varint + wire-type 解析。

支持 11 种消息类型：弹幕消息、礼物消息、用户进入/离开、点赞、关注/分享、观众人数等。

输出仅保存 `chat` 类型消息，字段精简为 `nickname` + `content` + `timestamp`。

#### 6. X-Bogus 签名 — 纯 Python 实现

1. 构建 query string → 追加 4 字节随机 nonce
2. RC4 加密（使用 Douyin 自定义 S-Box，密钥来自 User-Agent 的 MD5）
3. MD5 哈希
4. 自定义 Base62 编码 → `{encoded}_{nonce_hex}`

#### 7. 优雅关闭

- `SIGINT`/`SIGTERM` → `loop.call_soon_threadsafe(shutdown_event.set)`
- ffmpeg 停止: 先 `stdin.write(b"q\n")` → SIGTERM → SIGKILL 三级回退
- 弹幕连接: cancel asyncio task → `DanmakuClient.close()`
- 弹幕文件: 从 `.tmp` 读取所有行 → 写入格式化 JSON → 删除临时文件

---

## 技术栈

| 类别 | 技术 | 说明 |
|------|------|------|
| 语言 | Python 3.10+ | asyncio 异步架构 |
| 视频下载 | ffmpeg | `-c copy` 零损耗，异步子进程 |
| WebSocket | `websockets>=12.0` | 原生 asyncio 支持 |
| HTTP | `aiohttp>=3.9` | 异步 HTTP 请求 |
| 序列化 | 手动 Protobuf 解析 | 无需 protoc 编译 |
| 签名 | 纯 Python RC4+Base62 | 参见 signer.py |
| 浏览器自动化 | Playwright | 仅用于登录流程 |

---

## 技术难点与解决方案

### 1. Protobuf 字段号逆向

**问题**: 抖音弹幕使用私有 Protobuf schema，官方无文档。初始版本所有解析器字段号都错误。

**解决**: 在 `parser.py` 中输出 PushFrame 原始字段，定位到 `Response.messages[].method`，逐个消息类型确认字段结构。

### 2. Ctrl+C 无法停止录制

**问题**: Windows 下的信号处理器运行在独立线程中，直接调用 `asyncio.Event.set()` 不是线程安全的。

**解决**: 修改为 `loop.call_soon_threadsafe(shutdown_event.set)`，将事件设置操作调度到事件循环线程执行。

### 3. WebSocket 连接成功但无数据推送

**解决**:
- `cursor` 参数格式必须完全复刻浏览器
- `internal_ext` 格式必须匹配
- `user_unique_id` 必须是 12 位随机数字
- 建立连接后必须发送 `PushFrame{payloadType='msg'}` 订阅消息

### 4. 时区问题

**问题**: `datetime.now(timezone.utc)` 导致在中国使用时文件名显示 UTC 时间。

**解决**: 全部改为 `datetime.now()`（naive local time）。
