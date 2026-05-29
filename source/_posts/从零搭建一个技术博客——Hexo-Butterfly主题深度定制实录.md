---
title: 从零搭建一个技术博客——Hexo + Butterfly 主题深度定制实录
date: 2026-05-29 22:00:00
tags:
  - Hexo
  - Butterfly
  - GitHub Pages
  - CSS
  - Stylus
  - SEO
  - 前端优化
  - Markdown
  - JavaScript
  - Node.js
categories:
  - Web开发
description: 记录从零搭建 Hexo + Butterfly 技术博客的完整过程，涵盖主题定制、暗色模式、搜索集成、评论系统、文章抓取自动化、DOM 异常排查与缓存策略等实战细节。
---

## 一、项目概述

[黑岩的小屋](https://brszzz.github.io) 是一个面向安全研究与工具开发的技术博客，基于 Hexo 7.3.0 静态站点生成器与 Butterfly 5.5.4 主题搭建，部署于 GitHub Pages。博客目前包含 20 篇文章，涵盖 Android 逆向工程、Linux 内核调试、CTF 题解、直播工具开发与 AI 应用等方向。

### 技术栈一览

| 层面 | 技术选型 |
|------|---------|
| 静态站点生成 | Hexo 7.3.0 |
| 主题 | Butterfly 5.5.4 |
| 评论系统 | Utterances（GitHub Issues 驱动） |
| 站内搜索 | hexo-generator-search + Butterfly local_search |
| 部署 | hexo-deployer-git → GitHub Pages (gh-pages) |
| 文章抓取 | 自研 Python 脚本（52pojie.cn → Markdown） |
| CSS 预处理 | Stylus（Butterfly 原生支持） |
| 语法高亮 | highlight.js（darker 主题） |

---

## 二、搭建与基础配置

### 2.1 Hexo 初始化

Hexo 的初始化非常简洁，几条命令即可完成：

```bash
npm install -g hexo-cli
hexo init github-blog
cd github-blog
npm install
```

Butterfly 主题通过 npm 安装：

```bash
npm install hexo-theme-butterfly
```

然后在 `_config.yml` 中将主题设为 `butterfly`。

### 2.2 部署到 GitHub Pages

使用 `hexo-deployer-git` 插件，配置 SSH 免密推送：

```yaml
# _config.yml
deploy:
  type: git
  repo: git@github.com:brszzz/brszzz.github.io.git
  branch: gh-pages
```

每次发布只需执行：

```bash
hexo generate --deploy
```

`hexo generate` 将 Markdown 文章渲染为静态 HTML，`hexo deploy` 自动将 `public/` 目录推送到 `gh-pages` 分支。整个流程一键完成，无需 CI/CD 流水线。

---

## 三、主题深度定制

### 3.1 暗色模式全局改造

Butterfly 主题内置暗色模式，但默认的 `#121212` 纯黑背景对比度过高，长时间阅读容易疲劳。我决定将所有暗色背景统一调整为 `#4d4d4d`（炭灰色）。

主题的暗色变量定义在 `themes/butterfly/source/css/_mode/darkmode.styl`，这是一个 Stylus 文件。Strictly speaking 直接修改主题文件不是最佳实践（升级时会被覆盖），但在没有子主题机制的情况下，这是获得完全控制权的最快路径。

改动涉及约 25 个 CSS 变量：

```stylus
// darkmode.styl 中的关键变量
:root
  --global-bg: #4d4d4d
  --card-bg: #4d4d4d
  --font-color: #eee
  --code-background: #3a3a3a
  --blockquote-bg: #3a3a3a
  // ... 其余 20+ 个变量
```

同时，对于分页和推荐文章的卡片，进一步细化为 `#5a5a5a`，并调整了字体大小与卡片高度，使整体视觉层次更加分明。

### 3.2 毛玻璃导航栏与页脚

Butterfly 的导航栏支持 `fixed` 固定定位。利用 CSS 的 `backdrop-filter` 属性，可以轻松实现毛玻璃效果：

```css
#footer {
  background: rgba(77, 77, 77, 0.8) !important;
  backdrop-filter: blur(7px);
  -webkit-backdrop-filter: blur(7px);
}
```

导航栏的毛玻璃效果由主题原生支持，页脚则需要通过 Butterfly 的 `inject` 注入机制添加自定义 CSS。两者配合，形成了统一的视觉风格。

### 3.3 主题持久化

Butterfly 的主题切换使用 `localStorage` 存储用户偏好，但初始加载时依赖服务端配置的 `display_mode`。为了让用户的主题选择在页面导航时保持一致，需要在页面加载早期读取 `localStorage` 并设置 `data-theme` 属性。

Butterfly 内部使用 `btf.saveToLocal` 封装，存储格式为 JSON：

```javascript
{
  "value": "dark",  // 或 "light"
  "expiry": 1717200000000  // 过期时间戳
}
```

在 Butterfly 的 `inject.bottom` 中注入脚本，确保在其他 JS 执行前完成主题恢复：

```javascript
(function() {
  var t;
  try {
    var d = JSON.parse(localStorage.getItem('theme'));
    if (d && d.expiry > Date.now()) t = d.value;
  } catch(e) {}
  document.documentElement.setAttribute('data-theme', t || 'dark');
})();
```

### 3.4 头像黑边裁切

头像通过 `object-fit: cover` 在 110px 圆形容器中展示，但图片本身带有黑边。在不修改原图的前提下，使用 CSS `transform: scale()` 放大图片，配合父容器的 `overflow: hidden` 裁切掉黑边：

```css
.avatar-img img {
  transform: scale(1.15);
}
.avatar-img img:hover {
  transform: scale(1.15) rotate(360deg);
}
```

悬停时保留旋转动画，同时维持缩放比例。

---

## 四、站内搜索

Hexo 生态中有多种搜索方案，我选择了最轻量的 `hexo-generator-search`，它会在构建时生成一个 `search.xml` 文件，包含所有文章的标题、路径和正文内容。

配置分为两部分：

**Hexo 层**（`_config.yml`）：

```yaml
search:
  path: search.xml
  field: post
  content: true
```

**Butterfly 主题层**（`_config.butterfly.yml`）：

```yaml
search:
  use: local_search
  placeholder: 搜索文章...
  local_search:
    preload: false
    top_n_per_article: 1
```

关键点是 Butterfly 的搜索开关是 `search.use: local_search`，而不是 `search.local_search.enable: true`。这个配置差异是 Butterfly 特有的设计——它支持多种搜索后端（Algolia、本地搜索等），`use` 字段决定激活哪一个。

---

## 五、文章抓取自动化

博客中 15 篇逆向工程文章来自[吾爱破解论坛](https://www.52pojie.cn)。手动搬运效率低下，因此编写了一个 Python 爬虫 `scrape_52pojie.py`（363 行），自动化整个流程。

### 5.1 核心流程

```
论坛帖子 URL → HTTP 请求 → HTML 解析 → Markdown 转换 → 保存为 .md
```

### 5.2 技术要点

**请求处理**：使用 `urllib`（无第三方依赖），处理 gzip 压缩、GBK 编码、重试逻辑（3 次，5 秒退避）。

**HTML 解析**：纯正则表达式实现，不依赖 BeautifulSoup。论坛 HTML 结构复杂，包含多层 `<div>` 嵌套、JS 包裹的图片链接、多种代码块格式等。正则虽不如 HTML 解析器优雅，但在处理不一致的论坛标记时反而更灵活。

**代码块转换**：论坛使用 `<pre class="brush: LANG;">` 标记代码块，需要映射为 Markdown 的 fenced code block：

```python
LANG_MAP = {
    'c': 'c', 'cpp': 'cpp', 'java': 'java', 'python': 'python',
    'bash': 'bash', 'asm': 'asm', 'xml': 'xml', 'javascript': 'javascript',
}
# <pre class="brush:java;"> → ```java
```

**图片提取**：论坛图片通常以缩略图 + 原图的形式出现。原图 URL 藏在 `zoomfile` 或 `file` 属性中，需要优先提取。

**自动标签与分类**：通过约 40 组关键词映射自动打标签。分类则有优先级逻辑——CTF 文章归为"安全分析"，包含逆向关键词的归为"逆向工程"，内核/驱动相关归为"软件调试"。

**输出**：生成 YAML frontmatter（标题、日期、标签、分类、描述）+ Markdown 正文，直接保存到 Hexo 的 `source/_posts/` 目录。

---

## 六、DOM 异常排查：侧边栏位置错乱

这是开发过程中遇到的最隐蔽的 bug。

### 6.1 现象

在分页第 2 页和部分文章详情页，原本位于右侧的侧边栏（`#aside-content`）掉到了内容下方，页面布局完全错乱。

### 6.2 排查过程

初步怀疑是 CSS flexbox 布局问题。Butterfly 的 `.layout` 使用 `display: flex`，主内容区占 74%，侧边栏占 26%。但检查编译后的 CSS 和 HTML 结构，两页完全相同，没有发现 flex 相关差异。

然后怀疑是 `position: sticky` 导致了视觉偏移。侧边栏内部的 `.sticky_layout` 使用 sticky 定位，但 sticky 只在有滚动时生效，按理不应影响水平布局。

最后，通过编写一个 DOM 深度分析脚本，逐标签解析页面结构并计算嵌套层级，发现了关键差异：

```
PAGE1: #aside-content at depth 2, final depth: 1  (正常)
PAGE2: #aside-content at depth 4, final depth: 3  (异常)
```

侧边栏的嵌套深度多了 2 层，这意味着有未闭合的 HTML 标签被注入了 DOM。

### 6.3 根因

问题出在一篇 52pojie 转载文章的 frontmatter `description` 字段中：

```yaml
description: "...入口点果然被修改了，  ```xml <activity android:name=\"com.xxxx.xxx.MainActivity\" android:exported=\""
```

内联的 ` ```xml ` 代码块标记未被 Markdown 渲染器识别为代码块（代码块语法要求反引号在行首），其中的 `<activity android:name="...">` XML 标签被浏览器当作真实 HTML 元素解析，破坏了页面 DOM 结构。该文章只出现在分页第 2 页，恰好解释了 bug 的页面特异性。

同一篇文章的正文中还有更多未转义的 XML 标签（如 `<intent-filter>`、`<action>`、`<category>`），它们在 Markdown 正文中作为解释文字出现，同样被当作 HTML 注入页面。

### 6.4 修复

将所有非代码块内的 `<>` 转义为 `&lt;&gt;`：

```markdown
<!-- 修复前 -->
<activity>：此标签用于在AndroidManifest.xml文件中声明活动组件。

<!-- 修复后 -->
&lt;activity&gt;：此标签用于在AndroidManifest.xml文件中声明活动组件。
```

这个问题的教训是：在 Markdown 中引用 XML/HTML 标签时，务必转义尖括号，即使它们看起来像是会被代码块语法捕获。Markdown 渲染器对代码块的识别依赖于严格的格式（反引号必须在行首或仅有少量缩进），内联的反引号不会触发代码块模式。

---

## 七、浏览器缓存策略

### 7.1 问题

每次部署新内容后，访问页面显示的仍是旧版本，必须手动 Ctrl+F5 强制刷新。这是因为 GitHub Pages 为 HTML 文件设置了默认缓存头（`Cache-Control: max-age=600`，即 10 分钟），浏览器在这段时间内不会重新请求。

### 7.2 解决方案

在 Butterfly 的 `inject.head` 中注入缓存控制 meta 标签：

```html
<meta http-equiv="Cache-Control" content="no-cache">
```

这里 `no-cache` 的含义不是"禁止缓存"，而是"使用缓存前必须先向服务器验证"。实际行为是：

1. 浏览器发送条件请求（`If-None-Match` / `If-Modified-Since`）
2. 如果页面未变化，服务器返回 `304 Not Modified`，浏览器使用本地缓存
3. 如果页面有更新，服务器返回新内容

这说明 `no-cache` 在保持缓存优势的同时确保了内容新鲜度，是一个适合静态博客的折中方案。

---

## 八、文章提交与部署流程

Hexo 博客的文章发布遵循一条固定的流水线，掌握后只需两条命令即可完成。

### 8.1 文章文件结构

每篇文章是一个独立的 Markdown 文件，存放在 `source/_posts/` 目录下。文件命名采用 `标题.md` 格式，Hexo 会根据文件名和 frontmatter 中的日期生成最终 URL。

文件由两部分组成：

**YAML Frontmatter**（文章元数据）：

```yaml
---
title: 文章标题
date: 2026-05-29 22:00:00
tags:
  - 标签1
  - 标签2
categories:
  - 分类名
description: 文章摘要描述
---
```

**Markdown 正文**：标准 Markdown 语法，支持代码块、图片、表格等。

### 8.2 添加新文章

有两种方式创建新文章：

**方式一：Hexo 命令行创建**

```bash
hexo new post "文章标题"
```

这会在 `source/_posts/` 下生成一个带默认 frontmatter 的 `.md` 文件，然后编辑该文件填入内容即可。

**方式二：直接放置 Markdown 文件**

将写好的 `.md` 文件直接复制到 `source/_posts/` 目录下，确保 frontmatter 格式正确。这是批量导入或从外部来源获取文章时最常用的方式：

```bash
cp /path/to/文章.md source/_posts/
```

### 8.3 本地预览

在部署前建议先本地预览，确认排版和链接无误：

```bash
hexo server
```

启动后在浏览器访问 `http://localhost:4000` 即可查看。Hexo 会监听文件变化并自动刷新页面。

### 8.4 生成与部署

确认无误后，一条命令完成构建和发布：

```bash
hexo generate --deploy
```

这等价于先后执行：

```bash
hexo generate   # 将 Markdown 渲染为静态 HTML，输出到 public/ 目录
hexo deploy     # 将 public/ 推送到 GitHub Pages 的 gh-pages 分支
```

部署使用 `hexo-deployer-git` 插件，底层通过 `git push` 将构建产物推送到远程仓库的 `gh-pages` 分支。GitHub Pages 检测到分支更新后会自动部署上线，通常几秒内即可通过 `https://<username>.github.io` 访问到新内容。

### 8.5 完整工作流示例

以添加本文为例，完整流程如下：

```bash
# 1. 将写好的文章复制到 Hexo 文章目录
cp "D:/AI/Article/从零搭建一个技术博客——Hexo-Butterfly主题深度定制实录.md" \
   "D:/AI/github-blog/source/_posts/"

# 2. 生成并部署
cd D:/AI/github-blog
hexo generate --deploy
```

无需 CI/CD 流水线，无需操作 GitHub 网页端，整个发布流程控制在一条命令内。

---

## 九、总结

本项目从零搭建到上线，涉及了静态站点生成器的配置、CSS 主题定制、搜索与评论集成、自动化内容抓取、DOM 调试以及部署优化等多个方面。几个关键收获：

1. **先理解框架再定制**：Butterfly 的配置体系有自己的约定（如搜索的 `use` 字段），不能想当然地套用通用模式，需要阅读源码或文档确认。

2. **Markdown 中的 HTML 转义**：转载外部内容时，最容易被忽略的安全问题不是 XSS，而是 XML 标签破坏 DOM 结构。任何非代码块内的 `<tag>` 都需要转义。

3. **缓存策略需要精细权衡**：完全禁用缓存会损害性能，完全依赖默认缓存则影响更新时效。`no-cache` 提供了良好的中间地带。

4. **自动化脚本值得投入**：363 行的爬虫脚本虽然编写耗时，但它使 15 篇文章的批量导入成为可能，并留下了可持续复用的工具。
