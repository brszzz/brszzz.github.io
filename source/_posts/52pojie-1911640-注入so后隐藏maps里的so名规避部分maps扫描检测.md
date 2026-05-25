---
title: 注入so后隐藏maps里的so名，规避部分maps扫描检测
date: 2025-01-01 00:00:00
tags:
  - Frida
  - Linux内核
  - Ptrace
  - 内存管理
  - 注入技术
  - 脱壳
  - 虚拟机
categories:
  - 原创工具
description: "**0x00 前情提要**最近研究学习了安卓的一些linker机制和注入方法，想到目前厂商会在proc/xxxx/maps里检测特征的so名，而注入时，ptrace附加到进程->远程调用mmaps申请匿名内存段->把文件复制到内存中->远程调用dlopen加载在内存中的so，这个过程中不管fd是不是0都会在maps中显示so的路径（这点还没明白是为什么，按我的理解他dlopen加载的应该是内存中的"
---

**0x00 前情提要**最近研究学习了安卓的一些linker机制和注入方法，想到目前厂商会在proc/xxxx/maps里检测特征的so名，而注入时，ptrace附加到进程->远程调用mmaps申请匿名内存段->把文件复制到内存中->远程调用dlopen加载在内存中的so，这个过程中不管fd是不是0都会在maps中显示so的路径（这点还没明白是为什么，按我的理解他dlopen加载的应该是内存中的elf，理论上来说不应该有名字，有大佬的话可以解释一下）。然后就想着能不能把maps中so的名字给去掉，在网上查阅了一些资料，此篇仅作为学习记录。

**0x01 maps简要介绍**

在Linux中将进程虚拟空间中的一个段叫做虚拟内存区域VMA（Virtual Memory Area)。

VMA对应ELF文件中的segment。

ELF文件有section和segment的概念。

从链接的角度看，ELF是按照section存储的，事实也的确如此；从装载的角度看，ELF文件又按照segment进行划分，这是为了防止按照section装载时造成的内部碎片。

segment相当于是将多个属性（读写执行）相同的section合并在一起进行。program headers 存放segment的信息;section table存放section的信息.maps中每一个对应的项如下

![](https://attach.52pojie.cn/forum/202404/09/161059mdkx4303hdx4kzxt.png)

其中主要关注vm_flags和映射文件名

我是基于这个github项目的基础上添加的功能<blockquote>https://github.com/SsageParuders/AndroidPtraceInject</blockquote>

原项目直接注入的话会有注入路径名的特征

![](https://attach.52pojie.cn/forum/202404/09/162229pr1ts1qrz67p75qs.png)

![](https://attach.52pojie.cn/forum/202404/09/162419p73pjpp7jo77lyp7.png)

**0x02 如何实现隐藏内存段名**

灵感来自于之前看过的一篇帖子，帖子里讲的是有个应用做了一个操作，用dlopen加载so后，mmap一块新内存，把加载后的so内存memmove复制过去，然后mremap把原地址映射到新地址，这样maps里就没有这个so的信息了，能在一定程度上防止别人dump这个so（虽然好像现在来看没什么用）

mmove和mmap的函数原型如下

#define_GNU_SOURCE

#include<unistd.h>

#include<sys/mman.h>

void * mremap(void *old_address, size_t old_size , size_t new_size, int flags.../* void *new_address */);  //扩大/缩小现有内存映射，flags参数还可以控制是否需要页对齐

old_address：旧地址已经被page aligned页对齐

old_sixe：VMB虚拟内存块的大小

new_size：mremap操作后需要的VMB大小

flags：

MREMAP_MAYMOVE :允许内核将映射重定位到新的虚拟地址| MREMAP_FIXED:接受第五个参数void *new_address，该参数指映射必须移动到页面对齐地址page_align。在new_address和new_size指定的地址范围内的所有先前映射都不会被映射。如果指定了MREMAP_FIXED，还必须指定MREMAP_MAYMOVE

void * memmove(new_Address, old_Address, size); // 

new_Address:新地址 

old_Address:原地址, 

size：大小

1.首先还是按照正常步骤注入so，ptrace附加到进程->远程调用mmaps申请匿名内存段->把文件复制到内存中->远程调用dlopen加载在内存中的so。

2.然后在maps里搜索含有指定so的名称

[C] 纯文本查看 复制代码ProcMapInfo *ListModulesWithName(char *name, int pid)
{
 static ProcMapInfo returnVal[3];
 int i = 0;
 char buffer[512];
 char fielPath[100];
 sprintf(fielPath, "/proc/%d/maps", pid);
 printf(fielPath);
 FILE *fp = fopen(fielPath, "r");
 if (fp != nullptr)
 {
 while (fgets(buffer, sizeof(buffer), fp))
 {
 if (strstr(buffer, name))
 {
 ProcMapInfo info{};
 char perms[10];
 char path[255];
 char dev[25];

 sscanf(buffer, "%lx-%lx %s %ld %s %ld %s", &info.start, &info.end, perms, &info.offset, dev, &info.inode, path);

 // Process Perms
 if (strchr(perms, 'r'))
 info.perms |= PROT_READ;
 if (strchr(perms, 'w'))
 info.perms |= PROT_WRITE;
 if (strchr(perms, 'x'))
 info.perms |= PROT_EXEC;
 if (strchr(perms, 'r'))
 info.perms |= PROT_READ;

 // Set all other information
 info.dev = dev;
 info.path = path;

 printf("Line: %s", buffer);
 returnVal[i] = info;
 // printf("start:%lx-end:%lx", returnVal[i].start, returnVal[i].end);
 i++;
 }
 }
 }
 return returnVal;
}

这样就能获取到注入后so的内存区域地址，当然也可以在远程调用注入的时候用返回的指针获取分配的地址

3.然后就是再分配一块内存，把原内存的内容复制过去，再用remap扩展过去

[C] 纯文本查看 复制代码long int address = maps[i].start;
 size_t size = maps[i].end - maps[i].start;
 // printf("start:%lx-end:%lx\n", maps[i].start, maps[i].end);
 // void *map = mmap(0, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
 parameters[0] = 0; // 设置为NULL表示让系统自动选择分配内存的地址
 parameters[1] = size; // 映射内存的大小
 parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; // 表示映射内存区域 可读|可写|可执行
 parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
 parameters[4] = -1; // 若需要映射文件到内存中，则为文件的fd
 parameters[5] = 0; // 文件映射偏移量
 if (ptrace_call(pid, (uintptr_t)mmap_addr, parameters, 6, &CurrentRegs) == -1)
 {
 printf("[-] Call Remote mmap Func Failed, err:%s\n", strerror(errno));
 break;
 }
 uintptr_t newMapAddr = ptrace_getret(&CurrentRegs);
 if ((maps[i].perms & PROT_READ) == 0)
 {
 printf("Removing protection: %s", maps[i].path);
 // mprotect(address, size, PROT_READ);
 parameters[0] = address; // 设置为NULL表示让系统自动选择分配内存的地址
 parameters[1] = size; // 映射内存的大小
 parameters[2] = PROT_READ; // 表示映射内存区域 可读|可写|可执行
 if (ptrace_call(pid, (uintptr_t)mprotect_addr, parameters, 3, &CurrentRegs) == -1)
 {
 printf("[-] Call Remote mprotect Func Failed, err:%s\n", strerror(errno));
 break;
 }
 }

 // Copy to new location
 // memmove(map, address, size);
 parameters[0] = newMapAddr;
 parameters[1] = address;
 parameters[2] = size;
 
 if (ptrace_call(pid, (uintptr_t)memmove_addr, parameters, 3, &CurrentRegs) == -1)
 {
 printf("[-] Call Remote memmove Func Failed, err:%s\n", strerror(errno));
 break;
 }
 // mremap(map, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, maps[i].start);
 parameters[0] = newMapAddr;
 parameters[1] = size;
 parameters[2] = size;
 parameters[3] = MREMAP_MAYMOVE | MREMAP_FIXED;
 parameters[4] = maps[i].start;
 if (ptrace_call(pid, (uintptr_t)mremap_addr, parameters, 5, &CurrentRegs) == -1)
 {
 printf("[-] Call Remote mremap Func Failed, err:%s\n", strerror(errno));
 break;
 }

 // Reapply protection
 // mprotect((void *)maps[i].start, size, maps[i].perms);
 parameters[0] = address; // 设置为NULL表示让系统自动选择分配内存的地址
 parameters[1] = size; // 映射内存的大小
 parameters[2] = maps[i].perms; // 表示映射内存区域 可读|可写|可执行
 if (ptrace_call(pid, (uintptr_t)mprotect_addr, parameters, 3, &CurrentRegs) == -1)
 {
 printf("[-] Call Remote mprotect Func Failed, err:%s\n", strerror(errno));
 break;
 }

这样就完成了内存段的隐藏了，来看看效果

![](https://attach.52pojie.cn/forum/202404/09/170246rn9gz1bkmb569c5z.png)

![](https://attach.52pojie.cn/forum/202404/09/170848xe9ism28gagzaest.png)

现在内存里就看不到内存段的名字了

**0x03 后记**

隐藏了内存段的名字只能说规避掉一些特征检测，现在很多主流app还会检测内存里有没有可疑内存段，内存空间里虽然没了名字，但是r-xp这种代码段内存没名字本身就很可疑。发现匿名内存后，对这段内存做一些内存特征判断blablabla，也还有一堆其他的检测方法。

在别的地方看到的一些过检测的方法：内核代码中修改show_map_vma函数能实现对指定内存段的读写执行权限进行修改，甚至直接把这段内存全都过滤掉（内存不连续也是可疑的）。还有用frida+seccomp监控应用调用，过滤修改对maps的读取感觉也是可行的。

想要成为更好的人。

**参考：**

https://blog.csdn.net/weixin_41540614/article/details/111058417
