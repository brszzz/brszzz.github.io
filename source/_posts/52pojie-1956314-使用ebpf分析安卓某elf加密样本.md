---
title: 使用ebpf分析安卓某elf加密样本
date: 2025-01-01 00:00:00
tags:
  - ARM
  - DEX
  - Hook
  - Java
  - Linux内核
  - Root
  - eBPF
  - 脱壳
categories:
  - 逆向工程
description: "**0x0 前言** 
 今天记录一次对某安卓elf文件的加密分析的流程和使用ebpf的思路。 
 工具设备： 
 1.mi12 安卓12 内核5.10.136 
 2.stackplz  **0x1 十六进制dump（xxd）** 
 首先这个样本有两个文件，一个是elf可执行文件的启动器，一个是不知道什么格式的文件  ![](https://attach.52pojie.cn/forum/20"
---

### 0x0 前言

今天记录一次对某安卓elf文件的加密分析的流程和使用ebpf的思路。

工具设备：

1.mi12 安卓12 内核5.10.136

2.stackplz

### 0x1 十六进制dump（xxd）

首先这个样本有两个文件，一个是elf可执行文件的启动器，一个是不知道什么格式的文件

![](https://attach.52pojie.cn/forum/202408/20/111115t2yrqyheelh9hmzq.png)

那么先来看看这个xxxxx.lib是什么东西，用010editor打开看一眼

![](https://attach.52pojie.cn/forum/202408/20/111405j86std1gc7vraast.png)

看起来这是个加密过的文件，那么那个启动器大概率就是解密这个文件并执行，可是这个是什么加密现在还没办法完全判断，所以去启动器里找找线索，这个启动器是加的也是我之前说的那种壳。这次就来说一下偷懒不分析这个启动器，怎么用stackplz去获取他的解密方式。

先执行样本，然后ps -ef|grep start.sh找出他的pid

![](https://attach.52pojie.cn/forum/202408/20/113939tmqegfi9buwiz99u.png)

![](https://attach.52pojie.cn/forum/202408/20/114020kjwwfyja5qhrnqs5.png)

启动器如果想操作xxxx.lib文件的话肯定会用到read，write，exec这类的syscall，那么就用stackplz直接去监听它syscall的调用，./stackplz --pid '应用pid' --syscall '需要监听的系统调用'

![](https://attach.52pojie.cn/forum/202408/20/114721kqcibtsc3b558sas.png)

可是监听了一下发现start.sh并没有任何的系统调用，结合上次的分析，猜想他是另外开了一个线程或者执行了其他可执行文件，用inotifyd监控到了他是创建执行了这个文件（或者可以直接查start.sh的子进程） /data/user/0/com.xiaomi.aiasst.service/T1DsE17NWsJtOWhrcnLeh3PYy39nyqlUNQ9iyU28LiIOBtdmitoPexWW52AAD1Kr6VJ46FFeaRNeNgyUgbtqG6Agxt

于是对这个进程进行syscall的监听，监听到了exec的调用

```
findBTFAssets btf_file=a12-5.10-arm64_min.btf

can not find package for process_pid=20178

[*] save maps to maps_20178.txt

hook syscall count:2

ConfigMap{stackplz_pid=23825,thread_whitelist=0}

uid => whitelist:[];blacklist:[]

pid => whitelist:[20178];blacklist:[]

tid => whitelist:[];blacklist:[]

start 2 modules

[23857|23857|sh] execve(pathname=0xb4000078b482a468(/system/bin/xxd), argv=0xb4000078b484d750[

 0xb4000078b4805358(xxd),

 0xb4000078b4805318(-r),

 0xb4000078b4805368(-p),

 0xb4000078b482a408(xxxxx.lib)

], envp=0xb4000078b4855008[

 0xb4000078b482a448(_=/system/bin/xxd), 

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4ea80

[23888|23888|sh] execve(pathname=0xb4000078b482a448(/system/bin/mv), argv=0xb4000078b4806250[

 0xb4000078b4805338(mv),

 0xb4000078b482a368(xxxxx.lib),

 0xb4000078b482a408(/data/adb/)

], envp=0xb4000078b4855008[

 0xb4000078b482a428(_=/system/bin/mv),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4ea80

[23889|23889|sh] execve(pathname=0xb4000078b482a4e8(/system/bin/basename), argv=0xb4000078b4806250[

 0xb4000078b482a428(basename),

 0xb4000078b482a488(xxxxx.lib)

], envp=0xb4000078b4856008[

 0xb4000078b482a4c8(_=/system/bin/basename),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4e4e0

[23890|23890|sh] execve(pathname=0xb4000078b482a488(/system/bin/chmod), argv=0xb4000078b4806280[

 0xb4000078b4805338(chmod),

 0xb4000078b48052f8(777),

 0xb4000078b4806248(/data/adb/xxxxx.lib)

], envp=0xb4000078b4856008[

 0xb4000078b482a428(_=/system/bin/chmod),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4ea80

[23891|23891|sh] execve(pathname=0xb4000078b482a508(/system/bin/basename), argv=0xb4000078b4806220[

 0xb4000078b482a428(basename),

 0xb4000078b482a4c8(xxxxx.lib)

], envp=0xb4000078b4856008[

 0xb4000078b482a4e8(_=/system/bin/basename),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4e4e0

[23892|23892|sh] execve(pathname=0xb4000078b4806248(/data/adb/xxxxx.lib), argv=0xb4000078b482a430[

 0xb4000078b4806218(/data/adb/xxxxx.lib)

], envp=0xb4000078b4856008[

 0xb4000078b4806278(_=/data/adb/xxxxx.lib),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438baf8 PC:0x78b4db227c SP:0x7ff2a4ea80

[23892|23892|sh] execve(pathname=0xb4000078b4806248, argv=0xb4000078b482a430, envp=0xb4000078b4856008, ret=-8)

[23892|23892|sh] execve(pathname=0x5ee436c818(/system/bin/sh), argv=0xb4000078b482a428[

 0x5ee436c818(/system/bin/sh),

 0xb4000078b4806248(/data/adb/xxxxx.lib)

], envp=0xb4000078b4856008[

 0xb4000078b4806278(_=/data/adb/xxxxx.lib),

 0xb4000078b482a008(ANDROID_DATA=/data),

 0xb4000078b4806068(ANDROID_ART_ROOT=/apex/com.android.art),

 0xb4000078b4805208(HOME=/),

 0xb4000078b4824548(ANDROID_TZDATA_ROOT=/apex/com.android.tzdata),

 0xb4000078b4806098(ANDROID_ASSETS=/system/app),

 0xb4000078b482a088(TERM=xterm-256color),

 0xb4000078b482a028(ANDROID_SOCKET_adbd=19),

 0xb4000078b48060c8(ANDROID_STORAGE=/storage),

 0xb4000078b48060f8(EXTERNAL_STORAGE=/sdcard),

 0xb4000078b482a048(MEMTAG_OPTIONS=off),

 0xb4000078b4806128(DOWNLOAD_CACHE=/data/cache),

 0xb4000078b482a068(LOGNAME=root),

 0xb4000078b4815a08(SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/services.jar:/system_ext/framework/miui-services.jar:/system_ext/framework/miui-appcompat.jar:/system_ext/framework/miui-appcompat.appcontinuity.jar:/system_ext/framework/miui.services.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar),

 0xb4000078b481f288(STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar),

 0xb4000078b4830008(DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar),

 0xb4000078b482b008(BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/telephony-ext.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system_ext/framework/miui-framework.jar:/system_ext/framework/miui-telephony-common.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar),

 0xb4000078b482a0a8(SHELL=/system/bin/sh),

 0xb4000078b482a0c8(ANDROID_BOOTLOGO=1),

 0xb4000078b4806158(ASEC_MOUNTPOINT=/mnt/asec),

 0xb4000078b482a0e8(HOSTNAME=cupid),

 0xb4000078b482a108(USER=root),

 0xb4000078b482a128(TMPDIR=/data/local/tmp),

 0xb4000078b4833008(PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/data/adb/ksu/bin),

 0xb4000078b482a168(ANDROID_ROOT=/system),

 0xb4000078b48248c8(ANDROID_I18N_ROOT=/apex/com.android.i18n)

]) LR:0x5ee438d3c0 PC:0x78b4db227c SP:0x7ff2a4e9f0
```

execl第一个是命令文件的路径，第二个是执行的参数

那么他的操作就很明显了，用的十六进制dump，用 xxd -r -p ‘加密文件’  这个命令就能在terminal里获得真正的文件，在后面加上 >'解密文件'就能保存。   

```
xxd -r -p ‘加密文件’ >'解密文件'
```

然后就是mv移动到/data/local/tmp，chmod给777权限，sh执行

### 0x2 base64

解密后的文件里还有一个 echo '加密内容'| base64 -d|sh 这种的shell加密，直接把加密内容复制出来，找个base64网站解密就行，这个没啥好说的
> 
> https://www.toolhelper.cn/EncodeDecode/Base64

### 0x3 小结

这次偷懒成功，不多说了，黑神话启动！
