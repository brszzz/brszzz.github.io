---
title: dump网易加固的libUE4.so
date: 2025-01-01 00:00:00
tags:
  - Unreal
  - 内存管理
  - 加固
  - 脱壳
categories:
  - 原创工具
description: "**0x0 前言**  刚好最近有空，顺便再记录一下之前一次dump莉莉丝的farlight84 libUE4遇到的问题，他本来用的tx的安全，后面不知道为啥换成网易的。  **0x1 dump libUE4.so**  他这个so本身也是有加密的，需要dump加载解密后的libUE4.so，首先用ue4dumper尝试dump一下，结果发现提示不是elf文件。  ![](https://a"
---

**0x0 前言**

刚好最近有空，顺便再记录一下之前一次dump莉莉丝的farlight84 libUE4遇到的问题，他本来用的tx的安全，后面不知道为啥换成网易的。

**0x1 dump libUE4.so**

他这个so本身也是有加密的，需要dump加载解密后的libUE4.so，首先用ue4dumper尝试dump一下，结果发现提示不是elf文件。

![](https://attach.52pojie.cn/forum/202410/09/112802nq7jks5rj3jsbb3d.png)

他这个提示头错误不是elf文件，那可能就是elf头有问题，试试手动给他dump下来，首先找PID[Asm] 纯文本查看 复制代码ps -ef|grep farlight84

![](https://attach.52pojie.cn/forum/202410/09/113609zvqcv4abqz3zb4rl.png)

找到pid之后，用这个命令找到libUE4.so的起始地址和结束地址[Shell] 纯文本查看 复制代码cat /proc/25093/maps|grep libUE4

![](https://attach.52pojie.cn/forum/202410/09/114434ais63n2ozodr4idj.png)

用这个命令dump内存 skip=开始内存地址（10进制） count=dump内存大小（10进制）

[Shell] 纯文本查看 复制代码dd if=/proc/25093/mem of=/data/local/tmp/libUE4.so skip=502757203968 bs=1 count=371871744

![](https://attach.52pojie.cn/forum/202410/09/120148b7sv6vwjr88tsn2b.png)

ok,现在已经成功dump了内存了，那么接下来看看他这个到底是个什么东西。

**0x2 分析dump后的libUE4.so**

拖进010editor看看，果然不太对劲，elf头被修改了，怪不得

![](https://attach.52pojie.cn/forum/202410/09/121403gds5vzbwk2vedasb.png)

上面这个是dump后的libUE4头，下面这个是原版的libUE4头

![](https://attach.52pojie.cn/forum/202410/09/121513q9yxo6x1qq9nnhr9.png)

那么很简单，直接给他替换过去就行。

**0x3 修复dump后的libUE4.so**

这里用sofixer去修复， https://github.com/F8LEFT/SoFixer

![](https://attach.52pojie.cn/forum/202410/09/121946v0cxrvsxr5brub5s.png)

修复后的so ida能正常识别了

![](https://attach.52pojie.cn/forum/202410/09/122114lwyho31pdnakz3ly.png)

**0x4 小结**

至此，dump libUE4的流程就结束了，后面dumpSDK那些没什么额外的处理。其实后面继续逆向的时候发现，他这种处理方式会导致某些工具因为识别不到elf头，找不到libUE4，例如ce和用某些栈回溯工具。
