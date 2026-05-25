---
title: 斗鱼直播 AI 分析系统 — 项目文档
date: 2026-05-25 10:40:00
tags:
  - 斗鱼
  - AI分析
  - 直播
  - Python
  - DeepSeek
  - Claude
  - Whisper
  - 弹幕分析
  - 多模态
  - 高光识别
categories:
  - AI技术
description: 斗鱼直播自动录制+AI智能分析系统，通过DeepSeek/Claude大模型进行多维度分析，自动识别直播精彩片段和高光时刻
---

## 一、项目简介

本项目是一个**斗鱼直播自动录制 + AI 智能分析**系统，能够自动录制斗鱼直播间的视频流和弹幕数据，并通过大语言模型（DeepSeek V4 Pro / Claude Code）对录制内容进行多维度分析，自动识别直播中的精彩片段和高光时刻，最终输出结构化分析报告。

### 核心功能

1. **直播录制** — 同时录制 FLV 视频流和 JSONL 弹幕数据，支持 WebSocket/TCP 双通道弹幕采集
2. **音频转录** — 从 FLV 视频中提取音频，通过 Whisper 模型将主播语音转为带时间戳的文本
3. **弹幕分析** — 解析弹幕数据，计算密度曲线、检测峰值、提取热词
4. **视觉分析** — 从视频中按间隔提取关键帧，结合画面内容进行多模态分析
5. **AI 高光识别** — 将转录文本 + 弹幕数据 + 视频帧发送给 DeepSeek/Claude，由 AI 识别精彩片段
6. **报告导出** — 输出 JSON 和 Markdown 格式的结构化分析报告

### 工作流程

```
FLV 视频 ──→ ffmpeg 提取音频 ──→ Whisper 转录 ──→ 带时间戳文本段
    │                                                    │
    ├──→ ffmpeg 提取关键帧 ──→ Base64 画面数据           │
    │                                                    │
JSONL 弹幕 ──→ 时间归一化 ──→ 密度/峰值/热词分析          │
                                                         │
                    ┌────────────────────────────────────┘
                    ▼
         按 3 分钟窗口合并数据
                    │
                    ▼
         DeepSeek V4 Pro API (默认) 或 Claude Code CLI
                    │
                    ▼
         去重合并 → 结构化分析报告 (JSON + Markdown)
```

---

## 二、开发过程

### 2.1 分析器构建（迭代过程）

**Phase 1 — 基础框架搭建**
- 创建 `analyzer` 包，包含 `__init__.py`、`__main__.py`、`cli.py`
- 配置 `pyproject.toml`，添加 `openai`、`faster-whisper` 依赖
- 使用 Click 构建命令行界面

**Phase 2 — 弹幕加载与密度分析**
- 实现 `danmaku_loader.py`：解析 JSONL 弹幕文件，提取 6 种消息类型
- 实现 30 秒滑动窗口密度计算，标准差法自动检测密度峰值
- 实现 2-gram 短语热词提取

**Phase 3 — 音频提取与语音转录**
- 使用 ffmpeg 从 FLV 提取 16kHz 单声道 WAV 音频
- 集成 faster-whisper（base 模型），将语音转为带精确时间戳的文本段
- 转录结果缓存为 `.transcript.json`，避免重复处理

**Phase 4 — AI 高光分析核心**
- 基于 OpenAI SDK 调用 DeepSeek API（`deepseek-v4-pro`）
- 设计 System Prompt：多维度分析（语音、弹幕、画面），评分 0-10，10 种分类
- 按 3 分钟窗口分片处理长视频，每窗口独立请求 AI 分析
- 跨窗口结果去重合并，时间冲突按评分裁剪

**Phase 5 — 视觉多模态分析**
- 从视频按 60 秒间隔提取关键帧（ffmpeg 缩放至 512px，最大 20 帧）
- DeepSeek 后端：帧画面以 Base64 `image_url` 形式嵌入 API 请求
- Claude 后端：帧画面以文件路径引用

**Phase 6 — 双后端架构**
- 保留 DeepSeek API 作为默认后端（需 API key）
- 新增 Claude Code CLI 后端（`claude --print --output-format json`）
- 通过 `--backend` 参数切换

**Phase 7 — 问题修复与优化**
- 修复弹幕与视频时间对齐：文件名时间戳作为 T=0 基准
- 修复 FLV 元数据不完整导致时长获取失败：WAV 回退方案
- 修复 Claude CLI 输出非纯 JSON：多层 JSON 解析回退
- 优化片段产出量：降低评分门槛、缩小分析窗口、扩充分类体系

---

## 三、技术栈

| 层级 | 技术 | 用途 |
|------|------|------|
| **语言** | Python 3.10+ | 全部代码 |
| **CLI** | Click 8.x | 命令行界面 |
| **日志** | Loguru | 统一日志输出 |
| **录制** | aiohttp, asyncio | 异步视频流 + WebSocket/TCP 弹幕采集 |
| **协议** | 自定义二进制协议 | 斗鱼弹幕协议编解码 |
| **音视频处理** | ffmpeg, ffprobe | 音频提取、关键帧提取、时长获取 |
| **语音转文字** | faster-whisper (base) | 本地语音转录，中文识别 |
| **AI 分析（主）** | DeepSeek V4 Pro API | OpenAI 兼容接口，多模态视觉分析 |
| **AI 分析（备）** | Claude Code CLI | 本地调用，`--print` 非交互模式 |
| **AI SDK** | openai >= 1.0 | 统一 API 调用 |
| **数据格式** | JSONL (弹幕), JSON (缓存/报告), Markdown (报告) |

---

## 四、核心技术实现细节

### 4.1 弹幕时间对齐

**问题**：弹幕使用绝对 Unix 时间戳（`time.time()`），但视频分析需要相对于视频起始点的秒数。两者相差约 17 亿秒，无法直接对齐。

**最终方案**：**从文件名解析录制开始时间作为 T=0 基准**

```python
def parse_filename_timestamp(path: Path) -> float:
    match = re.search(r"(\d{8}_\d{6})", path.name)
    dt = datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
    return dt.timestamp()
```

所有弹幕时间戳减去该基准值后，转化为相对于录制开始的秒数，与视频时间轴精确对齐。

### 4.2 音频提取与语音转录

**音频提取**：
```bash
ffmpeg -y -nostdin -i input.flv -vn -acodec pcm_s16le -ar 16000 -ac 1 output.wav
```

- `-vn` 丢弃视频轨道
- `-acodec pcm_s16le` 无损 PCM 编码
- `-ar 16000 -ac 1` 16kHz 单声道（Whisper 标准输入）

**语音转录**：使用 faster-whisper base 模型（~140MB），CPU int8 量化推理。每个转录段包含 `[start, end, text]` 三元组，时间戳精度到毫秒级。

### 4.3 AI 分析核心

#### System Prompt 设计

关键设计要点：
- **多维度评分**：语音、弹幕、画面三个维度独立评估，任一维度有亮点即标记
- **宽松评分标准**：score ≥ 2 即可记录（最初为 ≥ 6，调整后大幅提升片段产出）
- **10 种分类**：精彩操作、搞笑互动、弹幕高潮、话题热议、礼物时刻、画面亮点、情绪激动、节奏变化、互动问答、新人涌入

#### 分片策略

长视频无法一次性发送给 AI（Token 限制 + 分析精度不足），采用 **3 分钟窗口分片**：

1. 转录文本按时间戳切分到对应窗口
2. 弹幕密度数据按窗口筛选
3. 视频帧按时间戳匹配到窗口（每窗口最多 6 帧，`detail: low` 控制成本）
4. 每个窗口独立请求 AI 分析
5. 跨窗口结果去重合并

#### DeepSeek 多模态调用

```python
client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")
response = client.chat.completions.create(
    model="deepseek-v4-pro",
    messages=[{
        "role": "system",
        "content": SYSTEM_PROMPT,
    }, {
        "role": "user",
        "content": [
            {"type": "text", "text": "转录文本 + 弹幕数据..."},
            {"type": "image_url", "image_url": {
                "url": "data:image/jpeg;base64,/9j/4AAQ...",
                "detail": "low",
            }},
        ],
    }],
    temperature=0.3,
    max_tokens=8192,
)
```

DeepSeek API 完全兼容 OpenAI SDK，只需修改 `base_url` 即可无缝切换。

#### Claude Code CLI 调用

```python
cmd = ["cmd", "/c", "claude", "--print", "--output-format", "json", "-p", prompt]
result = subprocess.run(cmd, capture_output=True, timeout=300)
```

`--output-format json` 将 Claude 输出包装为标准 JSON 信封，提取 `result` 字段后多层解析。

### 4.4 结果去重与冲突解决

AI 可能在相近时间输出多个相似片段，需要后处理去重：

**Step 1 — 语义去重**：同分类 + 同标题 + 时间段重叠 → 只保留第一个

**Step 2 — 时间冲突解决**：两片段有重叠时，高分覆盖低分

去重策略最终演变为严格的"不允许任何时间重叠"，确保每个时间点只属于一个高光片段。

### 4.5 缓存机制

| 缓存 | 路径 | 说明 |
|------|------|------|
| 转录缓存 | `{video}.transcript.json` | Whisper 转录结果，避免重复处理 |
| 帧缓存 | `{video}_frames/` | 关键帧 JPEG + 元数据 JSON |
| 音频缓存 | `{video}.wav` | 已提取音频，幂等跳过 |

---

## 五、核心技术难点

### 5.1 多模态时间对齐

三种数据源（视频帧、音频转录、弹幕）各自拥有独立的时间体系，通过以文件名中的录制开始时间为统一锚点，所有时间戳转化为相对秒数。

### 5.2 AI 输出质量控制

DeepSeek/Claude 的输出存在不稳定性，采用多层 JSON 解析器：直接解析 → Markdown 代码块提取 → JSON 对象边界查找，均失败则抛出明确错误信息。

### 5.3 长视频分析效率

- 3 分钟窗口分片，每窗口独立分析
- 弹幕数据用密度摘要替代逐条发送
- 视频帧每窗口最多 6 张（`detail: low` 降低 Token 消耗）

### 5.4 直播 FLV 文件元数据缺失

录制中的 FLV 文件 header 未写入完整时长信息，通过先提取音频为 WAV（格式完整），再回退到 WAV 获取时长。

---

## 六、项目使用

```bash
# 安装
pip install -e .

# 完整分析（音频转录 + 弹幕 + 视觉）
analyzer 24422

# 跳过转录（仅弹幕 + 视觉）
analyzer 24422 --no-transcribe

# 跳过视觉（仅文本 + 弹幕）
analyzer 24422 --no-vision

# 使用 Claude Code 本地分析
analyzer 24422 --backend claude

# 调整帧提取密度
analyzer 24422 --frame-interval 30
```

输出报告保存在 `./analysis/` 目录，包含 JSON 和 Markdown 两份文件。
