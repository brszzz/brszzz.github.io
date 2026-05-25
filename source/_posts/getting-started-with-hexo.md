---
title: Getting Started with Hexo Blog
date: 2026-05-25 11:00:00
tags:
  - hexo
  - tutorial
  - GitHub Pages
categories:
  - Tech
description: A quick guide to setting up a Hexo blog on GitHub Pages
---

## Prerequisites

Before getting started, make sure you have:

- [Node.js](https://nodejs.org/) installed
- [Git](https://git-scm.com/) installed
- A [GitHub](https://github.com/) account

## Quick Start

### 1. Install Hexo CLI

```bash
npm install -g hexo-cli
```

### 2. Create a New Blog

```bash
hexo init my-blog
cd my-blog
npm install
```

### 3. Start Writing

Create a new post:

```bash
hexo new "My First Post"
```

### 4. Preview

```bash
hexo server
```

Open `http://localhost:4000` to see your blog.

### 5. Deploy to GitHub Pages

Install the deployer plugin:

```bash
npm install hexo-deployer-git
```

Update `_config.yml` with your repository info:

```yaml
deploy:
  type: git
  repo: https://github.com/username/username.github.io.git
  branch: gh-pages
```

Then deploy:

```bash
hexo clean && hexo deploy
```

## Themes

Hexo has a rich theme ecosystem. The **Butterfly** theme used here is one of the most popular choices. To change themes:

1. Download a theme to the `themes/` folder
2. Update the `theme` field in `_config.yml`

## Conclusion

Hexo makes it incredibly easy to set up and maintain a blog. Combined with GitHub Pages, you get free, fast, and reliable hosting. Happy blogging!
