import urllib.request
import gzip
import re
import os
import html
import time
from pathlib import Path

URLS = [
    "https://www.52pojie.cn/thread-1991042-1-1.html",
    "https://www.52pojie.cn/thread-1983132-1-1.html",
    "https://www.52pojie.cn/thread-1980334-1-1.html",
    "https://www.52pojie.cn/thread-1977664-1-1.html",
    "https://www.52pojie.cn/thread-1975312-1-1.html",
    "https://www.52pojie.cn/thread-1970754-1-1.html",
    "https://www.52pojie.cn/thread-1970445-1-1.html",
    "https://www.52pojie.cn/thread-1956314-1-1.html",
    "https://www.52pojie.cn/thread-1952349-1-1.html",
    "https://www.52pojie.cn/thread-1951947-1-1.html",
    "https://www.52pojie.cn/thread-1922628-1-1.html",
    "https://www.52pojie.cn/thread-1922560-1-1.html",
    "https://www.52pojie.cn/thread-1911640-1-1.html",
    "https://www.52pojie.cn/thread-1792775-1-1.html",
]

OUTPUT_DIR = Path("D:/AI/Article")

FORUM_CATEGORIES = {
    "原创发布区": "原创工具",
    "脱壳破解区": "逆向工程",
    "移动安全区": "移动安全",
    "Android逆向": "移动安全",
    "iOS逆向": "移动安全",
    "编程语言区": "编程开发",
    "逆向资源区": "逆向资源",
    "病毒分析区": "安全分析",
    "软件调试区": "软件调试",
    "精品软件区": "软件推荐",
}

def fetch_page(url, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept-Language': 'zh-CN,zh;q=0.9',
            })
            resp = urllib.request.urlopen(req, timeout=30)
            raw = resp.read()
            if resp.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            return raw.decode('gbk', errors='replace')
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(5)
            else:
                raise e

def extract_thread_id(url):
    m = re.search(r'thread-(\d+)-', url)
    return m.group(1) if m else "unknown"

def extract_title(text):
    m = re.search(r'<span id="thread_subject">([^<]+)</span>', text)
    if m:
        return html.unescape(m.group(1).strip())
    m = re.search(r'<title>([^<]+)</title>', text)
    if m:
        title = m.group(1).strip()
        title = re.sub(r'\s*[-–—]\s*(?:吾爱破解|52pojie).*$', '', title)
        return html.unescape(title)
    return "Untitled"

def extract_date(text):
    m = re.search(r'发表于\s*(\d{4}-\d{1,2}-\d{1,2}\s*\d{1,2}:\d{1,2}(?::\d{1,2})?)', text)
    if m:
        date_str = m.group(1)
        parts = date_str.strip().replace('/', '-').split()
        date_part = parts[0]
        time_part = parts[1] if len(parts) > 1 else '00:00:00'
        y, mo, d = date_part.split('-')
        return f"{y}-{mo.zfill(2)}-{d.zfill(2)} {time_part}"
    return "2025-01-01 00:00:00"

def extract_forum_section(text):
    # Try fid-based link first
    m = re.search(r'<a href="forum\.php\?mod=forumdisplay[^"]*fid=(\d+)[^"]*"[^>]*>([^<]+)</a>', text)
    if m:
        return html.unescape(m.group(2).strip())
    # Try short format
    m = re.search(r'<a href="forum-(\d+)-1\.html"[^>]*>([^<]+)</a>', text)
    if m:
        return html.unescape(m.group(2).strip())
    return "未知分类"

def extract_post_content(text):
    m = re.search(r'<td class="t_f"[^>]*>(.+?)</td>', text, re.DOTALL)
    if not m:
        return ""
    content = m.group(1)

    # Remove <ignore_js_op> wrappers but keep image content
    content = re.sub(r'<ignore_js_op>(.*?)</ignore_js_op>', r'\1', content, flags=re.DOTALL)

    # Extract images from zoomfile/img tags
    def replace_img(m):
        zoomfile = re.search(r'zoomfile="([^"]+)"', m.group(0))
        file_attr = re.search(r'file="([^"]+)"', m.group(0))
        img_url = None
        if zoomfile:
            img_url = zoomfile.group(1)
        elif file_attr:
            img_url = file_attr.group(1)
        else:
            src = re.search(r'src="([^"]+)"', m.group(0))
            if src and 'none.gif' not in src.group(1) and 'static/image' not in src.group(1):
                img_url = src.group(1)
        if img_url:
            return f'\n![]({img_url})\n'
        return ''
    content = re.sub(r'<img[^>]*>', replace_img, content)

    # Remove tip/aimg_tip divs
    content = re.sub(r'<div class="tip[^"]*"[^>]*>.*?</div>', '', content, flags=re.DOTALL)

    # Remove pstatus edit notices
    content = re.sub(r'<i class="pstatus">[^<]*</i>', '', content)

    # Convert <br> to newlines
    content = re.sub(r'<br\s*/?>', '\n', content)

    # Convert <strong>/<b> to markdown bold
    content = re.sub(r'<(?:strong|b)>(.*?)</(?:strong|b)>', r'**\1**', content)

    # Strip <font> tags
    content = re.sub(r'</?font[^>]*>', '', content)

    # Convert links
    content = re.sub(r'<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', r'[\2](\1)', content)

    # Strip remaining HTML tags
    content = re.sub(r'</?(?:div|span|p|ul|ol|li|table|tr|td|th|tbody|thead|em|i|u|s|dl|dt|dd)[^>]*>', '', content)

    # Handle code blocks
    content = re.sub(r'<div class="blockcode"[^>]*>.*?<code>(.*?)</code>.*?</div>', r'\n```\n\1\n```\n', content, flags=re.DOTALL)
    content = re.sub(r'<code>(.*?)</code>', r'`\1`', content)

    # Handle quotes
    content = re.sub(r'<div class="quote"[^>]*>(.*?)</div>', r'\n> \1\n', content, flags=re.DOTALL)

    # Decode HTML entities
    content = html.unescape(content)

    # Clean whitespace
    content = re.sub(r'\n\s*\n\s*\n+', '\n\n', content)
    content = re.sub(r'[ \t]+', ' ', content)
    content = content.strip()

    return content

def generate_tags(title, forum_section, content):
    tags = set()

    section_lower = forum_section.lower()
    if '移动' in section_lower or 'android' in section_lower or '安卓' in section_lower:
        tags.add('Android')
    if 'ios' in section_lower or '苹果' in section_lower:
        tags.add('iOS')
    if 'windows' in section_lower:
        tags.add('Windows')
    if '脱壳' in section_lower or '破解' in section_lower:
        tags.add('逆向工程')
    if '编程' in section_lower:
        tags.add('编程开发')
    if '病毒' in section_lower:
        tags.add('安全分析')

    content_lower = (content + title).lower()
    keyword_map = {
        '内核': 'Linux内核', 'kernel': 'Linux内核',
        '驱动': '驱动开发',
        'hook': 'Hook', 'inline hook': 'Hook',
        '注入': '注入技术',
        'root': 'Root',
        'xposed': 'Xposed', 'lsposed': 'LSPosed',
        'frida': 'Frida',
        '脱壳': '脱壳', 'dump': '脱壳',
        '加固': '加固',
        'ollvm': 'OLLVM', '混淆': '代码混淆',
        'smali': 'Smali', 'dex': 'DEX',
        'ndk': 'NDK', 'jni': 'JNI',
        '断点': '断点调试', 'breakpoint': '断点调试',
        '编译': '编译', 'makefile': '编译',
        'python': 'Python', 'rust': 'Rust', 'c++': 'C++', 'java': 'Java',
        'arm': 'ARM', 'aarch': 'ARM64',
        '内存': '内存管理',
        'ptrace': 'Ptrace',
        '反调试': '反调试',
        '抓包': '抓包', 'charles': '抓包', 'fiddler': '抓包',
        '协议': '协议分析',
        '算法': '算法分析',
        'vm': '虚拟机', '模拟器': '模拟器',
        '游戏': '游戏安全', '外挂': '外挂分析',
        'ebpf': 'eBPF',
        'ctf': 'CTF', 'reverse': '逆向',
        'autoxjs': 'AutoXjs', 'autojs': 'AutoXjs',
        'ue4': 'Unreal', 'unreal': 'Unreal',
        'il2cpp': 'IL2CPP',
    }

    for keyword, tag in keyword_map.items():
        if keyword in content_lower:
            tags.add(tag)

    return sorted(list(tags))[:12]

def get_category(forum_section):
    for key, cat in FORUM_CATEGORIES.items():
        if key in forum_section:
            return cat
    if '移动' in forum_section or 'Android' in forum_section or '安卓' in forum_section:
        return '移动安全'
    if '脱壳' in forum_section or '破解' in forum_section or '逆向' in forum_section:
        return '逆向工程'
    if '编程' in forum_section:
        return '编程开发'
    if '原创' in forum_section:
        return '原创工具'
    return '技术分享'

def sanitize_filename(tid, title):
    # Use thread ID as primary identifier, add English-safe slug
    slug = re.sub(r'[^\w\s-]', '', title)
    slug = re.sub(r'[-\s]+', '-', slug)
    slug = slug.strip('-')[:60]
    return f"{tid}-{slug}.md" if slug else f"{tid}.md"

def scrape_all():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for i, url in enumerate(URLS):
        tid = extract_thread_id(url)
        print(f"[{i+1}/{len(URLS)}] Fetching thread {tid}...")

        try:
            text = fetch_page(url)
        except Exception as e:
            print(f"  ERROR fetching: {e}")
            continue

        title = extract_title(text)
        date = extract_date(text)
        forum_section = extract_forum_section(text)
        content = extract_post_content(text)
        tags = generate_tags(title, forum_section, content)
        category = get_category(forum_section)

        print(f"  Title: {title[:80]}")
        print(f"  Date: {date}")
        print(f"  Forum: {forum_section} -> Category: {category}")
        print(f"  Tags: {tags}")
        print(f"  Content: {len(content)} chars")

        # Description from first 200 chars of content, cleaned
        desc = content[:200].replace('\n', ' ').replace('"', '\\"')

        tags_yaml = '\n'.join(f"  - {tag}" for tag in tags)

        md = f"""---
title: {title}
date: {date}
tags:
{tags_yaml}
categories:
  - {category}
description: "{desc}"
---

{content}
"""

        filename = f"52pojie-{sanitize_filename(tid, title)}"
        filepath = OUTPUT_DIR / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)

        print(f"  Saved: {filename}")
        print()

        # Delay to avoid rate limiting
        if i < len(URLS) - 1:
            time.sleep(3)

if __name__ == '__main__':
    scrape_all()
