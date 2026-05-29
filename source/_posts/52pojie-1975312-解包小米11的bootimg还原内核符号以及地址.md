---
title: 解包小米11的boot.img，还原内核符号以及地址
date: 2025-01-01 00:00:00
tags:
  - DEX
  - Linux内核
  - Python
  - Root
categories:
  - 软件调试
description: "**0x0 前言** 
 因为一些教程过于老旧，为了防止自己以后重复踩坑，故记录一下学习过程中遇到的一些坑和现在有效的方法。 
 设备：mi 11 venus 内核版本5.4.210 
 **0x1 解包boot.img** 
 提取内核什么的就直接跳过，网上有很多资料都是可以直接用的，去官网下包或者有root的dd提取都可以。 
 首先先大概了解一下安卓内核 
 比较重要的几个分区如下： 
 1"
---

### 0x0 前言

因为一些教程过于老旧，为了防止自己以后重复踩坑，故记录一下学习过程中遇到的一些坑和现在有效的方法。

设备：mi 11 venus 内核版本5.4.210

### 0x1 解包boot.img

提取内核什么的就直接跳过，网上有很多资料都是可以直接用的，去官网下包或者有root的dd提取都可以。

首先先大概了解一下安卓内核

比较重要的几个分区如下：

1、/boot分区：该分区主要包含android kernel镜像和ramdisk（一种将RAM模拟为硬盘的技术，提高访问速度）。

2、/system分区：该分区主要存放Android框架及其相关配置，包含系统预装的app。

3、/recovery分区：该分区主要是备份的分区

4、/data 用户数据的存储区域

/data/app/com.xxxx/ 以包名存放应用安装文件，包括base.apk /lib

/data/data/com.xxxx/ 存放应用数据，包括sp、db等

/data/dalvik-cache 以包名存放优化过的应用dex文件

5、/cache分区：Android系统缓存区域，保存系统最常访问的数据和应用程序。

6、/misc分区：此分区包含一些系统功能设置开关和数据，比如USB设置。 

7、sdcard分区：外置存储分区

8、/vendor分区：厂商定制的分区，厂商的某些系统升级可以通过这个分区来实现。

boot.img就是android系统的Linux内核主要的镜像文件，在该文件中大致包含boot header，kernel，ramdisk。

boot.img文件跳过2K的文件头之后，包含两个gz压缩包，一个是boot.img-kernel.gz Linux内核，一个是boot.img-ramdisk.cpio.gz，然后加上ramdisk文件。

> 
> https://bbs.kanxue.com/thread-266625.htm

然后我按照这篇文章中的步骤尝试去提取kernel的时候发现里面的工具不能正常解析mi11的boot，尝试了其他的一些工具也无法正常提取

![](https://attach.52pojie.cn/forum/202410/24/160653iiiji3ci9mcp99pi.png)

![](https://attach.52pojie.cn/forum/202410/24/161313lxgw8ony6x9whk4r.png)

![](https://attach.52pojie.cn/forum/202410/24/160657rfroxto8nowx99ot.png)

正在我看他各种工具实现方法，binwalk解出来的包死活解压不了的时候，突然想起来很久之前root的时候看到的一个工具
> 
> https://github.com/affggh/magiskbootkitchen

用这个能正常提取，那就先偷个懒，以后有空再看看那些工具的原理和失效的原因，不过感觉是因为这个内核删掉了一些信息。

![](https://attach.52pojie.cn/forum/202410/24/162520wfvocwqftzfzyqhu.png)

用magiskbootkitchen提取之后，获得了两个文件

![](https://attach.52pojie.cn/forum/202410/24/162638njur8yxjraq8ljwx.png)

把文件放到ida里，能正常识别

![](https://attach.52pojie.cn/forum/202410/24/163124pypu12uvc7ttrl1v.png)

### 0x2 获取内核符号地址

然后就是获取内核符号地址了

首先先去除kptr_restrict，然后就能在  /proc/kallsyms里获得内核符号的地址

```
echo 0 > /proc/sys/kernel/kptr_restrict

cat /proc/kallsyms > kernel_symbols.txt
```

> 
> https://zhuanlan.zhihu.com/p/359234823

![](https://attach.52pojie.cn/forum/202410/24/164235zfz73qc3psk4wdkq.png)

我查资料正常来说内核的起始地址应该是0xffffffc000080000,但是我这个起始地址是0xFFFFFFE54F280000，在ida里重新设定基地址 Edit-->Segments--> Rebase Program，然后用python脚本按照kernel_symbols.txt里的对照关系把所有函数都重命名一下

```python
import idaapi

import idautils

import idc

 

def do_rename(l):

 splitted = l.split()

 straddr = splitted[0]

 strname = splitted[2].replace("\r", "").replace("\n", "")

 

 eaaddr = int(straddr, 16)

 idc.create_insn(eaaddr)

 ida_funcs.add_func(eaaddr)

 idc.set_name(int(straddr, 16), strname, idc.SN_NOWARN)

 

if __name__ == "__main__":

 ida_kernwin.msg("Hello IDC")

 f = open( "F:\\kernel_symbols.txt", "r")

 for l in f:

 do_rename(l)

 f.close()
```

这个是ida pro 7.7的,如果脚本语法版本不对的话
> 
> https://docs.hex-rays.com/archive/porting-guide-for-ida-7.4-turning-off-ida-6.x-api-backwards-compatibility-by-default

参考这个修改一下对应的函数。

看一下效果

![](https://attach.52pojie.cn/forum/202410/24/165310v1ejepjhqeerz7vr.png)

至此还原符号成功了。

### 0x3 小结

起始如果只是想看内核函数的话，之前有个大佬给的这个网址
> 
> https://elixir.bootlin.com/linux/v6.11.5/source

就能直接看各个版本内核函数的源码，不过各个厂商之间好像还是会有一些差距，用本文的方法还原出来的会更全一点。
