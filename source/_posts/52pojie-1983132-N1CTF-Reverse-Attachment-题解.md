---
title: N1CTF-Reverse-Attachment 题解
date: 2024-11-18 19:27
tags:
  - CTF
  - Frida
  - Hook
  - JNI
  - Java
  - 算法分析
  - 脱壳
  - 逆向
categories:
  - 原创工具
description: "**0x0 前言**  这道题根据出题人说，目前是只在安卓12和14上验证过，其他的系统可能会有问题，我刚开始是在mi11 安卓13上做的，输入假的flag依旧会弹出正确提示。猜测是frida hook java方法的时候某个地方出了问题，他是成功把callRabbit转换为jni函数并通过art_quick_generic_jni_trampoline调用，但可能entry_point_fro"
---

**0x0 前言**

这道题根据出题人说，目前是只在安卓12和14上验证过，其他的系统可能会有问题，我刚开始是在mi11 安卓13上做的，输入假的flag依旧会弹出正确提示。猜测是frida hook java方法的时候某个地方出了问题，他是成功把callRabbit转换为jni函数并通过art_quick_generic_jni_trampoline调用，但可能entry_point_fromjni之类的偏移出错了，他并没有执行预计的逻辑，而是直接返回原java函数执行，这个时候用高版本的frida hook一次callRabbit后，这道题就正常了。

![](https://attach.52pojie.cn/forum/202411/18/161037pzrhrmrpjmkdjkrr.png)

![](https://attach.52pojie.cn/forum/202411/18/161437uqmd1s1dnu1ljfdw.png)

**0x1 题解**

首先这道题是个apk，照例丢进jadx看一眼

需要关注的两个地方，一个是MainActivity加载的librefantazio.so，一个是java层的验证函数callRabbit

[Java] 纯文本查看 复制代码static {
 System.loadLibrary("refantazio");
 }
public class rabbitHole {
 public static String callRabbit(String flag) {
 byte[] inputBytes = flag.getBytes();
 byte[] tokenBytes = "TokenashiTokeari".getBytes();
 byte[] xorResult = new byte[inputBytes.length];
 int[] array = {50, 3, 10, 2, 21, 53, 1, 17, 73, 28, 14, 25, 1, 4, 0, 72, 116, 41, 7, 4, 9, 65, 26, 27, 73, 26, 0, 31, 69, 41, 23, 27, 49, 65, 75, 42, 25, 46, 14};
 for (int i = 0; i < inputBytes.length; i++) {
 xorResult[i] = (byte) (inputBytes[i] ^ tokenBytes[i % tokenBytes.length]);
 }
 int i2 = xorResult.length;
 if (i2 != array.length) {
 return "No no no! Rabbit shakes its head.";
 }
 for (int i3 = 0; i3 < xorResult.length; i3++) {
 if ((xorResult[i3] & UByte.MAX_VALUE) != array[i3]) {
 return "No no no! Rabbit shakes its head.";
 }
 }
 return "Rabbit is very happy.";
 }
}

按照这个算法还原回去，用java写的还原：

[Java] 纯文本查看 复制代码public static void main(String[] args) {
 // 定义固定的 token 字符串和 array 数组
 byte[] tokenBytes = "TokenashiTokeari".getBytes();
 int[] array = {50, 3, 10, 2, 21, 53, 1, 17, 73, 28, 14, 25, 1, 4, 0, 72, 116, 41, 7, 4, 9, 65, 26, 27, 73, 26, 0, 31, 69, 41, 23, 27, 49, 65, 75, 42, 25, 46, 14};
 // 初始化一个 byte 数组来存储 flag 的字节
 byte[] flagBytes = new byte[array.length];
 // 根据 array 和 tokenBytes 反向推导出 flag 的每个字节
 for (int i = 0; i < array.length; i++) {
 // 计算 xorResult[i] (即 array[i])，并通过 XOR 计算出 flagBytes[i]
 int xorResult = array[i] & 0xFF; // array[i] 的低 8 位
 byte tokenByte = tokenBytes[i % tokenBytes.length]; // token 字符串的字节
 // 反向推导出 flagBytes[i]
 flagBytes[i] = (byte) (xorResult ^ tokenByte);
 }
 // 将 byte 数组转换为字符串，得到 flag
 String flag = new String(flagBytes);
 System.out.println("推测的 flag 是: " + flag);
 }

最后还原出来的结果是flag{Try Harder! Flag is Not Here. OwO}，这个flag明显不对，但是当我把这个输入到这个apk里的时候它提示我通过了，用frida打印这个方法，提示是native方法，说明这个java方法是被转换为了native函数的

[Asm] 纯文本查看 复制代码function dumpjava() {
 Java.perform(function () {
 var targetClass = Java.use('com.android.refantazio.rabbitHole');
 console.log(targetClass.callRabbit);
 console.log(ptr(targetClass.callRabbit).add(30).readPointer());
});
[attach]2737261[/attach]
}

那就去ida里看看librefantazio.so干了啥。

[Asm] 纯文本查看 复制代码0x7D522C:
 sub_7D5068(v1);
 v2 = sub_1065070("frida");
 qword_1237AB8 = sub_7D69EC(v2);

有很多地方都有明显的frida字串特征，这是一个frida库，在JNIOnLoad里启动的，直接用CE搜Java.use,就能搜出来它的脚本：

![](https://attach.52pojie.cn/forum/202411/18/161025vqm1nx1ft0rljttq.png)

[JavaScript] 纯文本查看 复制代码function(e) {
 var a = Java.use("java.lang.String");
 // 如果输入的字符串长度不为41，返回错误信息
 if (41 != e.length) {
 return a.$new("No no no! Rabbit shakes its head.");
 }
 let t = [];
 let n = "n1cTfOwO".length;
 // 初始化t数组为0-255
 for (let i = 0; i < 256; i++) {
 t[i] = i;
 }
 let o = 0;
 // 使用"n1cTfOwO"进行置换初始化
 for (let i = 0; i < 256; i++) {
 o = (o + t[i] + "n1cTfOwO".charCodeAt(i % n)) % 256;
 [t[i], t[o]] = [t[o], t[i]];
 }
 let r = 0;
 o = 0;
 // 定义一个预定的数字数组
 let i = [
 59, 67, 58, 32, 172, 94, 161, 232, 59, 225,
 56, 210, 206, 94, 123, 253, 112, 252, 41, 136,
 71, 102, 81, 80, 128, 39, 22, 44, 176, 41,
 205, 197, 5, 247, 68, 151, 127, 29, 251, 58,
 85
 ];
 // 遍历输入字符串进行比对
 for (let n = 0; n < e.length; n++) {
 o = (o + t[r = (r + 1) % 256]) % 256;
 [t[r], t[o]] = [t[o], t[r]];
 let l = t[(t[r] + t[o]) % 256];
 // 如果解密结果与预定数字数组不匹配，返回错误信息
 if ((e.charCodeAt(n) ^ l) != i[n]) {
 return a.$new("No no no! Rabbit shakes its head.");
 }
 }
 // 如果匹配，返回成功信息
 return a.$new("Rabbit is very happy.");
}

这个一眼RC4算法，Key是n1cTfOwO

![](https://attach.52pojie.cn/forum/202411/18/160753e6g2kk636upg66gu.png)

解密得出flag为 flag{Fr1da_GuM_J5_1s_S0_Pow3rFu11l1l!!!!}

**0x2 碎碎念**

这道题比较坑的是frida有的版本不适配导致走了很多弯路，我一度觉得是不是hook了JAVA String类的getBytes、toString之类的一些方法，魔改了frida，使用了一些比较底层的接口，所以找不到它真正修改的地方，就一直在看frida的实现原理，结果后面问了一手发现就是frida的bug。不过在寻找解决方法的过程中阅读了frida的源码，也学到了很多frida具体的实现原理。

样本链接： 
<blockquote>https://wwuz.lanzouv.com/ih3NN2fg4h1g

密码:3x5q</blockquote>
