---
title: 单独编译安卓内核断点模块(rwProcMem33的hwBreakPointProcMoudle)
date: 2024-12-13 17:55
tags:
  - ARM
  - ARM64
  - Linux内核
  - 断点调试
  - 编译
  - 虚拟机
categories:
  - 原创工具
description: "**0x0 前言**  前段时间在研究安卓的硬件断点实现和原理，本来是想尝试移植到aptach的kpm，但是尝试后发现需要补的结构太多了，有的结构不补只有前向声明的话好像也有问题，比如说用register_user_hw_breakpoint注册的断点后用户层会直接卡死，内核层正常运行。结果补来补去最后发现还不如直接用内核源码去编译ko，遂决定先用着原版的那个内核断点模块。这篇文章记录一下编译的"
---

**0x0 前言**

前段时间在研究安卓的硬件断点实现和原理，本来是想尝试移植到aptach的kpm，但是尝试后发现需要补的结构太多了，有的结构不补只有前向声明的话好像也有问题，比如说用register_user_hw_breakpoint注册的断点后用户层会直接卡死，内核层正常运行。结果补来补去最后发现还不如直接用内核源码去编译ko，遂决定先用着原版的那个内核断点模块。这篇文章记录一下编译的过程和其中遇到的一些问题及解决方法，防止自己下次需要重新配置环境的时候踩坑。

**0x1 环境准备**

我只放链接吧，具体怎么配置网上都有很多方法

安卓机型:mi11 安卓13 内核5.4.210

[虚拟机](https://www.52pojie.cn/thread-661779-1-1.html)：vm-ware17pro 17.5.2 build-23775571    Ubuntu 22.04.2 LTS

make：GNU Make 4.3

交叉编译工具：aarch64-linux-android-4.9-toolchain-master 这个我是在这里下的  https://github.com/Adrilaw/aarch64-linux-android-4.9-toolchain ，或者可以用去官方的这里拉https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/，据说是一定要用安卓拉出来的这个。

内核源码：[https://github.com/MiCode/Xiaomi ... e/tree/venus-r-oss/](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/venus-r-oss/)

rwprocmem33：[https://github.com/abcz316/rwPro ... eakpointProcModule/](https://github.com/abcz316/rwProcMem33/blob/master/hwBreakpointProcModule/)

vscode：1.83.1

**0x2 编译及刷入内核模块**

预编译内核

1.在内核源码路径下执行shell 命令：make mrproper清除之前的配置文件。然后在自己手机下找到/proc/config.gz,这个是手机内核编译时的配置文件，解压后放到内核源码路径下，修改名称为.config

2.执行 make ARCH=arm64 CROSS_COMPILE=/patch/aarch64-linux-android-4.9-toolchain-master/bin/aarch64-linux-android- menuconfig

3.选择Enable loadable module support（选择和取消是y和n建），然后做如下配置，或者直接在config里修改CONFIG_MODULES=y CONFIG_MODULE_UNLOAD=y

![](https://attach.52pojie.cn/forum/202412/13/161031jrhqprkqh57okrvb.png)

4.选择General setup->Preemption Model(......)->Preemptible Kernel,或者直接在config里修改CONFIG_PREEMPT=y

![](https://attach.52pojie.cn/forum/202412/13/161944ecwpqbp05cr4p9i4.png)

5.输入make ARCH=arm64 CROSS_COMPILE=/patch/aarch64-linux-android-4.9-toolchain-master/bin/aarch64-linux-android- prepare，等待执行完成

编译内核模块：

1.打开ver_control.h,#define MY_LINUX_VERSION_CODE KERNEL_VERSION(x,x,x),这里x,x,x修改成自己的内核版本。这里定义的版本是用于判断是否大于4.14.83，大于时需要引入额外的头文件

2.打开makefile，修改两处:   

        1).KDIR := /你的内核源码路径   

        2).CROSS_COMPILE=/交叉编译工具路径/bin/aarch64-linux-android-

3.cd到rwprocmem33的hwBreakpoointProc目录下，shell命令执行 make，结束后会在当前目录生成ko文件

4.输入modinfo xxxxx.ko,可查看当前内核模块的信息，主要观察vermagic，这个待会会用到

问题1：

接下来就是把ko文件push到手机/data下的任意路径，然后执行shell命令 insmod xxxx.ko，这个时候它提示 insmod: failed to load XXX.ko: Exec format error，用dmesg看内核日志发现他报的是这个错

[Asm] 纯文本查看 复制代码hwBreakpointProc1: version magic '5.4.61-qgki SMP preempt mod_unload modversions aarch64' should be '5.4.210-qgki-xxxxxxxxxx SMP preempt mod_unload modversions aarch64'

这是因为vermagic不对导致的，修改vermagic的方式在   /内核源码路径/include/linux/vermagic.h。这个VERMAGIC_STRING就是最后合成的VERMAGIC

![](https://attach.52pojie.cn/forum/202412/13/163641gxathtqak8l2aw8l.png)

那个UTS_RELEASE定义在 /内核源码目录/include/linux/utsrelease.h，这个文件是在make prepare之后才会生成的，直接在这个文件里修改保存就行。修改完之后进入rwprocmem33的hwBreakpoointProc目录下先make clean，然后再make一次。make成功后，用modinfo再看一次vermagic，确认后之前报错提示的那个一致就行，至此就可以成功加载那个ko文件了。

问题2：

过程中他一直报这个错warning: ISO C90 forbids mixed declarations and code [-Wdeclaration-after-statement]，还有一些跟这个C90标准相关的警告，而且他会把警告当成错误在make语句中添加编译选项都没用。查看报错，他是在/内核源码/scripts/gcc-wrapper.py报的，解决方法为注释掉run_gcc()里的interpret_warning(line)

**0x3 小结**

这篇文章大概记录了一下单独编译安卓内核模块的流程，其实中间还遇到了很多奇葩的问题，比如说因为中间换了几次交叉编译工具，导致内核的编译标准跟模块的不一致，导致编译失败等。因为是上周完成的所以有些问题不记得也无法复现了，后续想起来或者有人问的话了再更新吧。
