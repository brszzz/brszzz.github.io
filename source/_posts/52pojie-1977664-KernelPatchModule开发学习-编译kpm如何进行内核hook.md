---
title: KernelPatchModule开发学习-编译kpm、如何进行内核hook
date: 2024-11-01 17:39
tags:
  - ARM
  - ARM64
  - C++
  - Hook
  - Linux内核
  - 编译
  - 虚拟机
categories:
  - 原创工具
description: "**0x0 前言**  随着安卓逆向研究已经开始进入内核时代，现在内核相关的开发软件和资料也是越来越多。最近发现apatch的kpm挺好用的，不依赖内核源码，编译也很方便，还有现成的几种内核hook方式。但是在学习的过程中发现目前相关资料还是比较少，于是想用文章记录一下自己的学习过程。  **0x1 ****简介、****环境**   什么是KernelPatchModule？  官网的简"
---

**0x0 前言**

随着安卓逆向研究已经开始进入内核时代，现在内核相关的开发软件和资料也是越来越多。最近发现apatch的kpm挺好用的，不依赖内核源码，编译也很方便，还有现成的几种内核hook方式。但是在学习的过程中发现目前相关资料还是比较少，于是想用文章记录一下自己的学习过程。

**0x1 ****简介、****环境**

 什么是KernelPatchModule？

官网的简介：一些代码在内核空间运行，类似于Loadable Kernel Modules（LKM）。此外，KPM提供在内核空间进行内联hook、系统调用表hook的能力。KPM 是一个 ELF 文件，可由 KernelPatch 在内核空间内加载和运行。

官方GitHub地址

<blockquote>https://github.com/bmax121/KernelPatch/tree/dev</blockquote>

环境、工具版本：

Ubuntu 22.04.2 LTS

gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf.tar

GNU Make 4.3

**0x2 编译**

首先在官网下一份源码

![](https://attach.52pojie.cn/forum/202411/01/170709q5fhpdiyorwhdleh.png)

我们这里只需要关心kpms里的例子是怎么写的

然后是在这下载GNU tools ，建议使用aarch64-none-elf，我之前使用linux自带的aarch64-linux-gnu编译出来无法正常使用。

https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads/11-2-2022-02进入/kpms/demo-hello这个目录下

[Shell] 纯文本查看 复制代码export TARGET_COMPILE=$(yourPath)/aarch64-none-elf-
make

![](https://attach.52pojie.cn/forum/202411/01/170644t3nu5c52c26355t5.png)

输出的.kpm就是编译出来的模块

在apatch里内核模块->右下角图标->加载->选择hello.kpm,加载成功后会显示

![](https://attach.52pojie.cn/forum/202411/01/170647gybby4cgbb6y85pb.jpg)

使用demsg|grep kp就能看到模块加载的信息

![](https://attach.52pojie.cn/forum/202411/01/170646uzyj7dlleimsdjd0.png)

**0x3 kpm代码的基本结构**

需要关注的是这些地方

[C++] 纯文本查看 复制代码///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-hello-demo");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("AKI");

///< The description.
KPM_DESCRIPTION("KernelPatch Module AKI Test");

#define KPM_INIT(fn) \
 static mod_initcall_t __kpm_initcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.init"))) = fn

#define KPM_CTL0(fn) \
 static mod_ctl0call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl0"))) = fn

#define KPM_CTL1(fn) \
 static mod_ctl1call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl1"))) = fn

#define KPM_EXIT(fn) \
 static mod_exitcall_t __kpm_exitcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.exit"))) = fn

#endif
KPM_INIT(hello_init); 
KPM_CTL0(hello_control0);
KPM_CTL1(hello_control1);
KPM_EXIT(hello_exit); 

其中：

KPM_INIT(hello_init);   //kpm加载时调用的函数KPM_CTL0(hello_control0);  //在apatch中传入参数调用的函数

KPM_CTL1(hello_control1);//在apatch中传入参数调用的函数

KPM_EXIT(hello_exit); //卸载kpm调用的函数

**0x4 根据内核符号地址hook内核函数**

以hook process_vm_rw为例子，这个函数在/ mm / process_vm_access.c。

首先需要找到函数原型，可以结合我上一篇还原内核符号的文章和那个查看内核符号的网站使用。

函数原型：

[C++] 纯文本查看 复制代码static ssize_t process_vm_rw(pid_t pid,
 const struct iovec __user *lvec,
 unsigned long liovcnt,
 const struct iovec __user *rvec,
 unsigned long riovcnt,
 unsigned long flags, int vm_write) //5.4.210内核源码的函数原型

想要hook这个函数，首先在文件中按照原来的代码构建一个原型：

[C++] 纯文本查看 复制代码ssize_t (*process_vm_rw)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt,
 const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags, int vm_write) = 0;

使用kallsyms_lookup_name，在/kernel/include/kallsyms.h中，作用是寻找返回所查找的内核函数地址，找不到返回0。具体详见  https://blog.csdn.net/weixin_45030965/article/details/132497956

查找内核符号地址：

[C++] 纯文本查看 复制代码process_vm_rw = (typeof(process_vm_rw))kallsyms_lookup_name("process_vm_rw");

进行inline hook,hook_wrapX,这个X代表的是需要几个参数，里面调用的是hook_wrap()。before是调用前执行的函数，after是调用后执行的函数:

[C++] 纯文本查看 复制代码hook_wrap8((void *)process_vm_rw, before, after, 0);

**0x5 syscallHook**

根据系统调用号hook内核函数，以例子中的__task_pid_nr_ns这个函数为例，这个内核函数在/kernel/pid.c

根据系统调用号进行hook，分两种function_pointer_hook和inline_hook，他们调用的方式都是类似的

[C++] 纯文本查看 复制代码#define __NR_openat 56
err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);

关于这个工具hook syscall的具体原理流程后续随缘更新，这里就只讲使用。

**0x6 小结**

如果想知道具体kpm是如何加载运行的话，需要先了解APatch是如何运行的，这个现在还在看kptools的源码，还是后续随缘更新，感兴趣的可以先看看https://bbs.kanxue.com/homepage-935696.htm这个大佬的文章。
