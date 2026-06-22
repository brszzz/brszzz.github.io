---
title: Web FLV 视频播放器 — 项目技术文档
date: 2026-06-03 14:41:00
tags:
  - FLV
  - flv.js
  - Canvas
  - 弹幕
  - HTML5
  - JavaScript
  - 前端开发
categories:
  - Web开发
description: 基于 Web 的 FLV 视频播放器，支持本地文件播放、直播录制边录边播、弹幕实时渲染和 Hexo 博客部署，使用 flv.js + Canvas 实现。
---

## 项目概述

一个基于 Web 的 FLV 视频播放器，支持**本地文件播放**、**直播录制边录边播**、**弹幕实时渲染**和**Hexo 博客部署**。使用 flv.js 通过 Media Source Extensions 解码 FLV 文件，通过 File System Access API 读取本地文件夹，Canvas 实时渲染弹幕并支持碰撞避让。

- **语言**: HTML/CSS/JavaScript (纯前端)
- **许可**: 内部使用
- **部署**: Hexo + Butterfly 主题博客

---

## 使用方法

### 本地开发

```bash
# 启动开发服务器
python server.py

# 浏览器打开
# http://localhost:5174/player.html
```

### 基本操作

1. 点击文件夹图标，选择包含 `.flv` 文件的本地文件夹
2. 播放器自动发现同目录下的弹幕文件（文件名含 `danmaku`，`.json` 或 `.tmp` 结尾）
3. 支持直播录制场景 — 文件边录边写时，播放器自动检测文件增长并重建播放器

### 键盘快捷键

| 键 | 功能 |
|---|---|
| `Space` | 播放 / 暂停 |
| `←` `→` | 后退 / 前进 5 秒 |
| `F` | 全屏 |
| `M` | 静音 |

### 弹幕设置

| 设置项 | 说明 | 默认值 |
|--------|------|--------|
| 显示弹幕 | 开关 | 开 |
| 密度 | 同时显示弹幕数量上限 | 30 |
| 透明度 | 弹幕不透明度 | 0.8 |
| 字号 | 弹幕字体大小 | 20px |
| 位置 | 弹幕显示区域（全屏/上部/中部/下部） | 全屏 |
| 时间偏移 | 弹幕时间轴偏移量（秒） | 0 |

### 部署到 Hexo 博客

将 `player.html` 复制到 Hexo 的 `source/video-player/index.html`，添加 frontmatter：

```yaml
---
layout: false
---
```

在 Butterfly 主题 `_config.butterfly.yml` 中添加菜单项：

```yaml
menu:
  video player: /video-player/ || fas fa-play
```

---

## 项目架构

### 目录结构

```
web-video-palyer/
├── player.html          # 主播放器页面（~1600 行单文件）
├── server.py            # 开发用 HTTP 服务器（CORS + Range）
├── README.md            # 项目说明
└── .gitignore
```

```
github-blog/
├── _config.butterfly.yml           # Butterfly 主题配置
└── source/video-player/
    └── index.html                   # 博客部署副本（含 frontmatter）
```

### 数据流

```
用户选择文件夹
  │
  ▼
[File System Access API]  showDirectoryPicker()
  │
  ├──► .flv 文件 → FileSystemFileHandle
  │       │
  │       ▼
  │   [extractFlvInitSegment()]  提取 FLV Header + Script Tag + Codec Config
  │       │
  │       ▼
  │   [createVirtualUrl()]  创建 flv-live:// 虚拟 URL
  │       │
  │       ▼
  │   [window.fetch 拦截]  getFile() → 处理 Range → 返回 Response
  │       │
  │       ▼
  │   [flv.js]  FLV 解复用 → MP4 fMP4 → Media Source Extensions
  │       │
  │       ▼
  │   <video>  播放
  │
  └──► .json/.tmp 弹幕文件
          │
          ▼
      [loadDanmaku()]  JSONL / 嵌套 JSON 双格式解析
          │
          ▼
      [danmakuLoop()]  Canvas requestAnimationFrame 实时渲染
          │
          ▼
      <canvas>  弹幕叠加层
```

### 核心设计

#### 1. 虚拟 URL + Fetch 拦截系统

Chrome 对 `URL.createObjectURL(file)` 创建的对象 URL 有安全限制：当底层文件被修改（直播录制持续写入）时，访问该 URL 会抛出 `ERR_UPLOAD_FILE_CHANGED`。

解决方案：自定义 `flv-live://` 协议 + monkey-patch `window.fetch`：

```javascript
const _fetchHandles = new Map(); // virtualUrl → {handle, initHeader?, fileOffset?}

// 拦截 fetch
window.fetch = async function(url, options) {
    const entry = _fetchHandles.get(urlStr);
    if (!entry) return _origFetch.call(window, url, options);  // 非虚拟 URL，走原生 fetch

    const file = await entry.handle.getFile();  // 每次请求重新读取，天然支持文件增长
    // 构建响应：initHeader (可选) + file[fileOffset:] (可选)
    // 支持 HTTP Range 请求
    return new Response(new Blob(parts).stream(), { status, headers });
};

function createVirtualUrl(handle, initHeader, fileOffset) {
    const url = 'flv-live://player/' + (id++) + '/stream.flv';
    _fetchHandles.set(url, { handle, initHeader, fileOffset });
    return url;
}
```

**关键设计**：
- 每次请求都调用 `handle.getFile()` 获取最新文件内容 — 直播录制文件增长自动反映
- `initHeader` — FLV 初始化段（Header + Script Tag + Codec Config），重建播放器时前置
- `fileOffset` — 文件偏移量，重建时跳过已播放的字节
- 完整支持 HTTP Range 请求（flv.js seek 依赖）

#### 2. FLV 初始化段提取 (`extractFlvInitSegment()`)

从 FLV 文件头部读取固定字节数，提取解码器初始化所需的最小数据：

```
FLV 文件结构:
[9B Header] [4B PrevTagSize] [11B TagHeader + Data] [4B PrevTagSize] ...

提取策略：
1. 读取前 2MB 数据
2. 定位第一个 PreviousTagSize (offset 9)
3. 遍历所有 Tag，收集：
   - Script Tag (type=18) → 完整的脚本数据 (metadata)
   - Video Tag → 只保留第一个（包含 AVCDecoderConfigurationRecord）
   - Audio Tag → 只保留第一个（包含 AudioSpecificConfig）
4. 打包为: FLV Header + Script Tag + Video Config Tag + Audio Config Tag
```

#### 3. Seek 重建机制 (`rebuildPlayerAt()` + `findFlvSyncPoint()`)

当用户拖进度条到未缓冲区域时，需要重建播放器：

1. **估算字节偏移**: `byteOffset = targetTime / duration * fileSize`（假设恒定码率）
2. **查找同步点** — `findFlvSyncPoint()` 从估算位置向后扫描，找到合法的 FLV Tag 边界：
   - 读取 256KB 从估算位置开始
   - 找到有效的 PreviousTagSize → 向前找到 Tag Header
   - 验证 `TagType ∈ {8,9,18}` 且 `DataSize ∈ (0, 50MB)`
   - 连续两个合法 Tag 确认同步点
3. **构建虚拟 URL**: `createVirtualUrl(handle, flvHeader, syncByte)` — 前置初始化段，跳过已播放数据
4. **销毁旧播放器** — detach + destroy + 清理 MediaSource sourceBuffers
5. **创建新播放器** — flv.js 从头解码新流（timestamp 由 flv.js 自动处理为相对时间）

```javascript
async function rebuildPlayerAt(targetTime) {
    // 重新读取文件句柄获取最新大小
    state.flvFile = await state._flvFileHandle.getFile();
    const syncByte = await findFlvSyncPoint(state.flvFile, byteOffset);
    const newUrl = createVirtualUrl(state._flvFileHandle, state._flvHeader, syncByte);
    // 清理旧播放器 → 创建新播放器 → 加载新 URL
    state._timeOffset = targetTime;  // 新流的时间基点
}
```

#### 4. 直播录制轮询 + 自动重建

每 2 秒检查文件是否增长，播放到缓冲末尾时自动重建：

```
startPolling() → setInterval(checkFileGrowth, 2000)

checkFileGrowth():
  1. handle.getFile() → 检查 size 是否增长
  2. 更新 _estDuration 估算（等比缩放）
  3. 10s 冷却检查（防止频繁重建）
  4. 比较 playerTime vs bufferedEnd（MediaSource 相对时间）
  5. 播放位置距缓冲末尾 < 3s → rebuildPlayerAt(absoluteTime)
  6. 同步刷新弹幕文件
```

**关键教训**: 重建后 `video.buffered.end()` 是 MediaSource 相对时间（从 0 开始），而 `getCurrentTime()` 加了 `_timeOffset`（绝对时间）。必须使用 `flvPlayer.currentTime`（相对时间）与 `bufferedEnd` 比较，否则重建条件永远为真。

#### 5. 弹幕渲染引擎 (`danmakuLoop()`)

基于 `requestAnimationFrame` 的 Canvas 实时渲染：

- **滚动算法**: 匀速直线运动，速度 = `DANMAKU_SPEED` (200px/s)
- **碰撞避让**: 多条轨道（lane），每条弹幕占用一条轨道，同轨道弹幕不重叠
  - 每条弹幕记录结束位置（右侧 x 坐标）
  - 新弹幕从最小轨道号开始尝试，找到第一条空闲轨道
  - 轨道高度 = 字号 × 1.6
- **暂停冻结**: 暂停时 `lastDanmakuTs = 0` → 跳过位置更新 → 弹幕停在原位；播放时恢复滚动
- **增量加载**: 维护 `danmakuIndex` 指针，精确时间匹配（`videoTime ≥ currentTime && videoTime < currentTime + interval`）

#### 6. 弹幕双格式解析 (`loadDanmaku()`)

兼容两种弹幕文件格式：

```javascript
// 格式 1: 嵌套 JSON
{"events": [{"nickname": "...", "content": "...", "timestamp": 1716172800000}]}

// 格式 2: JSONL (每行一个 JSON)
{"nickname": "...", "content": "...", "timestamp": 1716172800000}
```

解析策略：先尝试 `JSON.parse` 整个文件查找 `events` 字段，失败后按行 JSONL 解析。

#### 7. 全屏控制栏自动隐藏

全屏模式下，控制栏 3 秒无操作自动淡出，移动鼠标恢复：

```javascript
// mousemove → show → 3s timer → hide (opacity: 0, pointer-events: none)
// 底部触发区域保留 pointer-events，鼠标接触底部 20px 区域时自动显示
```

---

## 技术栈

| 类别 | 技术 | 说明 |
|------|------|------|
| 视频解码 | flv.js 1.6.2 (CDN) | FLV → fMP4 via Media Source Extensions |
| 弹幕渲染 | Canvas 2D | requestAnimationFrame 实时绘制 |
| 文件读取 | File System Access API | Chrome/Edge 本地文件夹选择 |
| URL 方案 | 自定义 fetch 拦截 | 绕过 Chrome blob URL 限制 |
| 部署 | Hexo 7.3.4 + Butterfly 5.5.4 | 静态博客 |
| 开发服务器 | Python http.server | CORS + Range 支持 |

**浏览器要求**: Chrome / Edge（需支持 File System Access API）

---

## 技术难点与解决方案

### 1. `ERR_UPLOAD_FILE_CHANGED` — 直播录制文件无法播放

**问题**: Chrome 对 `URL.createObjectURL(file)` 创建的 Blob URL 有安全限制：当底层文件被修改（直播录制持续写入）时，访问该 URL 会抛出 `ERR_UPLOAD_FILE_CHANGED` 导致播放失败。

**解决**: 实现虚拟 URL + fetch 拦截系统：
- 用自定义 `flv-live://` 协议替代 Blob URL
- Monkey-patch `window.fetch` 拦截虚拟 URL 请求
- 每次请求调用 `FileSystemFileHandle.getFile()` 获取最新文件内容
- 支持 HTTP Range 请求（flv.js seek 依赖）
- 支持 `initHeader` 前置（重建时需要）+ `fileOffset` 偏移（跳过已播放部分）

### 2. 弹幕文件无法解析（嵌套 JSON vs JSONL）

**问题**: `20260601_171045.danmaku.json` 是嵌套 JSON 格式 `{"events":[...]}`，而代码仅支持 JSONL 格式（每行一个 JSON）。

**解决**: 实现双格式自动检测：先 `JSON.parse` 整个文件查找 `events` 字段，失败后按行 JSONL 逐行解析。

### 3. 弹幕暂停时无法冻结

**问题**: 暂停时在 `danmakuLoop` 中提前 `return`（不渲染），浏览器可能在帧间清空 Canvas，导致弹幕消失。

**解决**: 暂停时仍然渲染（`ctx.clearRect` + 重绘所有活跃弹幕），但跳过位置更新（`dt = 0`）和新弹幕生成。播放时恢复 `dt` 计算，弹幕从冻结位置继续滚动。

### 4. 直播轮询时间对比错误

**问题**: 重建播放器后，`getCurrentTime()` 返回 `_timeOffset + playerTime`（绝对时间），而 `video.buffered.end()` 是 MediaSource 相对时间（从 0 开始）。直接比较 `getCurrentTime() >= bufferedEnd - 3` 在重建后永远为真，导致不断触发重建。

**解决**: 使用 `flvPlayer.currentTime`（MediaSource 相对时间）与 `bufferedEnd` 比较，两者在同一时间基准。`absoluteTime = playerTime + state._timeOffset` 传给 `rebuildPlayerAt`。

### 5. Fetch 拦截器中 ArrayBuffer.stream() 报错

**问题**: 虚拟 URL 的 init header 是 `ArrayBuffer` 类型，当请求范围完全落在 init header 内时，只有单个 `ArrayBuffer` 被推入 `parts` 数组。代码优化路径 `parts[0].stream()` 对 `ArrayBuffer` 不可用（`ArrayBuffer` 没有 `.stream()` 方法）。

**解决**: 移除单元素优化，始终使用 `new Blob(parts).stream()` — `Blob` 构造函数接受 `ArrayBuffer` 参数。

### 6. Seek 后播放失败（FLV 同步点查找）

**问题**: 直接从估算字节位置切割 FLV 文件时，可能切在 Tag 中间位置，导致 flv.js 无法解码。

**解决**: 实现 `findFlvSyncPoint()` — 从估算位置向后扫描，通过验证 PreviousTagSize + Tag Header 结构的完整性，找到第一个合法的 FLV Tag 边界。同时前置 FLV 初始化段（Header + Script Tag + Codec Config），flv.js 才能正确初始化解码器。

### 7. 博客部署缓存问题

**问题**: `hexo deploy` 拷贝旧的 `public/` 文件夹，不包含最新修改。

**解决**: 必须先 `hexo clean && hexo generate && hexo deploy`，确保重新生成静态文件后再部署。

---

## 开发记录

### Phase 1: 基础播放器
- FLV 文件播放 (flv.js + MSE)
- File System Access API 文件夹选择
- 基本控制栏（播放/暂停、进度条、音量、静音）

### Phase 2: 弹幕系统
- Canvas 弹幕渲染引擎（requestAnimationFrame）
- 多轨道碰撞避让
- JSONL + 嵌套 JSON 双格式解析
- 暂停冻结/播放恢复

### Phase 3: Seek 重建
- FLV 初始化段提取
- FLV 同步点查找算法
- 播放器重建机制（切片 + 前置 Header）
- 内存泄漏修复（清理 sourceBuffers）

### Phase 4: 全屏与控制栏
- 全屏 API 集成
- 控制栏 3 秒自动隐藏
- 设置面板（密度、透明度、字号、位置、时间偏移）
- 键盘快捷键

### Phase 5: 直播录制支持
- FileSystemFileHandle 持久化
- 轮询检测文件增长 (2s 间隔)
- 自动重建播放器
- `_initialLoadDone` 标志防止初始加载期间误触发
- 10s 冷却防止频繁重建

### Phase 6: 虚拟 URL + Fetch 拦截
- `ERR_UPLOAD_FILE_CHANGED` 问题分析
- 虚拟 URL 系统 (`flv-live://` 协议)
- `window.fetch` monkey-patch
- HTTP Range 支持
- `initHeader` 前置 + `fileOffset` 偏移支持
- 全链路 blob URL → 虚拟 URL 迁移

### Phase 7: 博客部署
- Hexo + Butterfly 配置
- `layout: false` frontmatter
- 菜单项 + 新标签页打开
- 博客 favicon 一致性

### Phase 8: Bug 修复
- 弹幕双格式兼容
- 暂停冻结渲染修复（始终渲染，跳过更新）
- 轮询时间对比修复（MediaSource 相对时间 vs 绝对时间）
- `ArrayBuffer.stream()` 报错修复（始终用 `new Blob(parts).stream()`）
- 重建后 duration 更新

---

## 依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| flv.js | 1.6.2 (CDN) | FLV 解码库 |
| Chrome / Edge | 最新版 | File System Access API 支持 |
| Python | 3.x | 开发服务器 (`server.py`) |
| Hexo | 7.3.4 | 博客框架（部署用） |

---

## 操作说明

| 操作 | 效果 |
|------|------|
| 点击文件夹图标 | 选择包含 .flv 和弹幕文件的本地文件夹 |
| `Ctrl+C` (服务器) | 停止开发服务器 |
| `hexo clean && hexo g && hexo d` | 部署到 GitHub Pages |
| 拖进度条到未缓冲区域 | 触发 seek 重建 |
| 暂停 | 弹幕冻结在原地 |
| 全屏 | 控制栏 3 秒自动隐藏 |
