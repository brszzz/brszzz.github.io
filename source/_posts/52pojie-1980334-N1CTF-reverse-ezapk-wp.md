---
title: N1CTF-reverse-ezapk wp
date: 2025-01-01 00:00:00
tags:
  - CTF
  - DEX
  - Frida
  - Hook
  - JNI
  - Java
  - Root
  - 代码混淆
  - 内存管理
  - 算法分析
  - 逆向
categories:
  - 安全分析
description: "**0x0 前言** 
 前几天忙别的去了，完全忘了N1CTF，今天想着看看题学习一下，先只下了个最简单的ezapk，结果晚上网站直接关服务器，下不了其他题了。。 
 这个是入门题，无混淆，反调和检测，flag格式为n1ctf{xxxxxxxxxxxxxxxxxxxxx} 
 **0x1 frida+jadx、ida静态分析** 
 我这台手机ida动调不知道为啥一直用不了，所以这里只用frida"
---

### 0x0 前言

前几天忙别的去了，完全忘了N1CTF，今天想着看看题学习一下，先只下了个最简单的ezapk，结果晚上网站直接关服务器，下不了其他题了。。

这个是入门题，无混淆，反调和检测，flag格式为n1ctf{xxxxxxxxxxxxxxxxxxxxx}

### 0x1 frida+jadx、ida静态分析

我这台手机ida动调不知道为啥一直用不了，所以这里只用frida。

首先安装apk，打开就是一个输入框和确认按钮，先拖进jadx里看一眼，入口就是MainActivity

```java
public class MainActivity extends AppCompatActivity {

 private ActivityMainBinding binding;

 public native String enc(String str);

 public native String stringFromJNI();

 @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity

 public void onCreate(Bundle bundle) {

 super.onCreate(bundle);

 ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());

 this.binding = inflate;

 setContentView(inflate.getRoot());

 this.binding.CheckButton.setOnClickListener(new View.OnClickListener() { // from class: com.n1ctf2024.ezapk.MainActivity$$ExternalSyntheticLambda0

 @Override // android.view.View.OnClickListener

 public final void onClick(View view) {

 MainActivity.this.m157lambda$onCreate$0$comn1ctf2024ezapkMainActivity(view);

 }

 });

 }

 public /* synthetic */ void m157lambda$onCreate$0$comn1ctf2024ezapkMainActivity(View view) {

 String obj = this.binding.flagText.getText().toString();

 if (obj.startsWith("n1ctf{") && obj.endsWith("}")) {

 if (enc(obj.substring(6, obj.length() - 1)).equals("iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A=")) {

 Toast.makeText(this, "Congratulations!", 1).show();

 return;

 } else {

 Toast.makeText(this, "Try again.", 0).show();

 return;

 }

 }

 Toast.makeText(this, "Try again.", 0).show();

 }

 static {

 System.loadLibrary("native2");

 System.loadLibrary("native1");

 }

}
```

很容易得出，他是加载了libnative1.so和libnative2.so，然后这个enc应该就是加密的函数，是在加载的so里实现的,输入是把n1ctf{}去掉，取括号中间的字串，处理完返回跟"iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A= "这个字串做对比，java层就没啥好看的了，主要看看native里enc是怎么实现的。

但是在导出里面并没有看到enc这个函数，首先想到的是一般jni传输字串会用GetStringUTFChars，hook libart的这个调用，hook脚本：

```javascript
 

 const lib_art = Process.findModuleByName('libart.so');

 const symbols = lib_art.enumerateSymbols();

 for (let symbol of symbols) {

 var name = symbol.name;

 if (name.indexOf("art") >= 0) {

 if ((name.indexOf("CheckJNI") == -1) && (name.indexOf("JNI") >= 0)) {

 if (name.indexOf("GetStringUTFChars") >= 0) {

 console.log('start hook', symbol.name);

 Interceptor.attach(symbol.address, {

 onEnter: function (arg) {

 console.log('GetStringUTFChars called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

 },

 onLeave: function (retval) {

 console.log('onLeave GetStringUTFChars:', ptr(retval).readCString())

 }

 })

 }

 }

 }

 }
```

果然给我逮到了,我的输入是n1ctf{testinput}

```
GetStringUTFChars called from:

0x796711117c libnative1.so!0x1b17c

0x796711117c libnative1.so!0x1b17c

0x7967eb9084 base.odex!0x1e084

0x7967eb9084 base.odex!0x1e084

onLeave GetStringUTFChars: testinput
```

于是能定位到native1的sub_1B148这个函数就是enc，然后大概看了一眼native2,发现里面都是一些加密算法，以下是函数名

```
iusp9aVAyoMI_XOR .text 000000000000106C 000000B4 00000050 R . . . . B T .

eeg0QuqIZtRO .text 0000000000001120 000000D0 00000050 R . . . . B T .

zWfl19ATrZaj .text 00000000000011F0 000000D0 00000050 R . . . . B T .

SZ3pMtlDTA7Q_RC4_0 .text 00000000000012C0 000002BC 000001A0 R . . . . B T .

H4AQFGSOe2Df_RC4_1 .text 000000000000157C 00000284 00000190 R . . . . B T .

MaR0Ssaa7zE9_RC4_2 .text 0000000000001800 000002B0 000001A0 R . . . . B T .

UqhYy0F049n5_Base64_0 .text 0000000000001AB0 000002FC 000000A0 R . . . . B T .

T6AAHJ6ZpxWI_Base64_1 .text 0000000000001DAC 000002FC 000000A0 R . . . . B T .

.
```

对这些函数批量frida-trace hook，发现调用的是iusp9aVAyoMI->0x106c和SZ3pMtlDTA7Q->0x12c0，分别对应EOR和RC4加密

```

Started tracing 15 functions. Web UI available at http://localhost:12651/

 /* TID 0x3874 */

 1056 ms sub_106c()

 1056 ms Backtrace:

0x796711127c libnative1.so!0x1b27c

0x7967eb9084 base.odex!0x1e084

0x7967eb9084 base.odex!0x1e084

 1246 ms sub_12c0()

 1246 ms Backtrace:

0x796711136c libnative1.so!0x1b36c

0x7fece42cf80x7fece42cf8
```

但是其中有个地方很奇怪，他加密用的key是rand()返回的随机数

```
_BYTE *__fastcall iusp9aVAyoMI_XOR(__int64 a1, size_t a2)

{

 size_t i; // [xsp+0h] [xbp-40h]

 _BYTE *v4; // [xsp+8h] [xbp-38h]

 v4 = malloc(a2);

 __memcpy_chk(v4, a1, a2, -1LL);

 for ( i = 0LL; i < a2; ++i )

 v4[i] ^= rand(); //这里不应该是rand()，应该是个固定的数

 return v4;

}

_BYTE *__fastcall SZ3pMtlDTA7Q_RC4_0(__int64 a1, int a2)

{

...

0x133c:

for ( i = 0; i < 16; ++i )

*((_BYTE *)v20 + i) = rand(); //这里不应该是rand()，应该是个固定的数

...

}

```

理论上来说key不应该是随机的，于是用CE去看了看内存，发现果然rand被修改过，修改的是native2的got表里的rand_ptr，修改为了native1里的sub_1B140的地址（现在好像上传不了图片，后续再补几张CE的图），这个函数返回的是key：0xE9。他替换应该是在native1里的1B540里，是被声明为了__attribute((constructor))的，so一加载就会调用这个函数，通过maps定位到native2的起始地址并对40f70做初始化，然后通过字串找到rand的地址并进行替换。

![](https://attach.52pojie.cn/forum/202411/12/020817ksdizw8shixviqph.png)

![](https://attach.52pojie.cn/forum/202411/12/020821twn0k47r2hzrw5yz.png)

最后附一个enc的修复吧

```
targetString = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 0x548LL))(

 a1,

 a3,

 0LL); // GetStringUTFChars

 targetString_1 = targetString;

 if ( (((1LL << (0xB9F51095uLL >> unk_40FA4)) | 0x200000) & ~*(_QWORD *)(qword_40FA8 + 8LL * (0x2E7D442u % unk_40FA0))) == 0 )

 {

 v7 = *(_DWORD *)(qword_40FB0 + 4LL * (0xB9F51095 % dword_40F98));// v7 = 14

 if ( v7 )

 {

 v8 = *(_DWORD *)(qword_40FB8 + 4LL * (unsigned int)(v7 - dword_40F9C));// v7=14 40F9C=11

 if ( (v8 ^ 0xB9F51094) >= 2 )

 {

 v5 = 1LL;

 while ( (v8 & 1) == 0 )

 {

 v9 = 1 - dword_40F9C + v7; // v9 = 4

 v5 = (unsigned int)++v7;

 v8 = *(_DWORD *)(qword_40FB8 + 4LL * v9);

 if ( (v8 ^ 0xB9F51094) < 2 )

 goto LABEL_9;

 }

 }

 else

 {

 LODWORD(v5) = *(_DWORD *)(qword_40FB0 + 4LL * (0xB9F51095 % dword_40F98));

LABEL_9: // v7 = 152, v8 = 0x1

 v5 = *(_QWORD *)(qword_40F78 + 0x18LL * (unsigned int)v5 + 8);// v5 = 152 ,v5 = 0x1a9f37e8eb090108

 }

 }

 }

 libnative2_iusp9aVAyoM_XOR = (__int64 (__fastcall *)(const char *, __int64))(elfHead_40F70 + v5);

 v11 = __strlen_chk(targetString, 0xFFFFFFFF);

 v12 = (const char *)libnative2_iusp9aVAyoM_XOR(targetString_1, v11);// rand被替换成了sub_1b140 key 233

 v14 = v12;

 if ( (((1LL << (0xD0C97EE3uLL >> unk_40FA4)) | 0x800000000LL) & ~*(_QWORD *)(qword_40FA8

 + 8LL * (0x34325FBu % unk_40FA0))) == 0 )

 {

 v15 = *(_DWORD *)(qword_40FB0 + 4LL * (0xD0C97EE3 % dword_40F98));

 if ( v15 )

 {

 v16 = *(_DWORD *)(qword_40FB8 + 4LL * (unsigned int)(v15 - dword_40F9C));

 if ( (v16 ^ 0xD0C97EE2) >= 2 )

 {

 v13 = 1LL;

 while ( (v16 & 1) == 0 )

 {

 v17 = 1 - dword_40F9C + v15;

 v13 = (unsigned int)++v15;

 v16 = *(_DWORD *)(qword_40FB8 + 4LL * v17);

 if ( (v16 ^ 0xD0C97EE2) < 2 )

 goto LABEL_18;

 }

 }

 else

 {

 LODWORD(v13) = *(_DWORD *)(qword_40FB0 + 4LL * (0xD0C97EE3 % dword_40F98));

LABEL_18:

 v13 = *(_QWORD *)(qword_40F78 + 0x18LL * (unsigned int)v13 + 8);

 }

 }

 }

 libnative2_SZ3pMtlDTA7Q_RC4 = (__int64 (__fastcall *)(const char *, __int64))(elfHead_40F70 + v13);// Key 233

 v19 = __strlen_chk(v12, 0xFFFFFFFF);

 v20 = (const char *)libnative2_SZ3pMtlDTA7Q_RC4(v14, v19);

 v22 = v20;

 if ( (((1LL << (0x5BBF417BuLL >> unk_40FA4)) | 0x800000000000000LL) & ~*(_QWORD *)(qword_40FA8

 + 8LL * (0x16EFD05u % unk_40FA0))) == 0 )

 {

 v23 = *(_DWORD *)(qword_40FB0 + 4LL * (0x5BBF417Bu % dword_40F98));

 if ( v23 )

 {

 v24 = *(_DWORD *)(qword_40FB8 + 4LL * (unsigned int)(v23 - dword_40F9C));

 if ( (v24 ^ 0x5BBF417Au) >= 2 )

 {

 v21 = 1LL;

 while ( (v24 & 1) == 0 )

 {

 v25 = 1 - dword_40F9C + v23;

 v21 = (unsigned int)++v23;

 v24 = *(_DWORD *)(qword_40FB8 + 4LL * v25);

 if ( (v24 ^ 0x5BBF417Au) < 2 )

 goto LABEL_27;

 }

 }

 else

 {

 LODWORD(v21) = *(_DWORD *)(qword_40FB0 + 4LL * (0x5BBF417Bu % dword_40F98));

LABEL_27:

 v21 = *(_QWORD *)(qword_40F78 + 24LL * (unsigned int)v21 + 8);

 }

 }

 }

 libnative2_UqhYy0F049n5_Base64 = (__int64 (__fastcall *)(const char *, __int64))(elfHead_40F70 + v21);

 v27 = __strlen_chk(v20, 0xFFFFFFFF);

 v28 = libnative2_UqhYy0F049n5_Base64(v22, v27);

 return (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)a1 + 0x538LL))(a1, v28);
```

拿flag也很简单，用iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A=先base64解密，得到891ACBEB7B6F7BE1FBDB08EBFC71E2C2556EE51654F570DC23B0，用rc4解密，key是0xe9，得到A4909ABDDA9BD8D99C9AB6AAD98DDAB6DBD9DBDDA7D8AABDAFC8，再用异或解密，key也是0xe9，得到MysT3r10us_C0d3_2024N1CTF!，所以最后的flag就是n1ctf{MysT3r10us_C0d3_2024N1CTF!}

### 0x3 小结

https://wwuz.lanzouv.com/iXmd02euer8b

这是修复过的so和apk本体，有兴趣的可以看看，总体来说还是比较简单的。不过这个rand()被修改让我想起来之前看到过的一个wg样本，有人为了过代码段的校验，也是替换tp那个tersafe got表的memcpy_ptr，通过检查src和长度是否覆盖到已修改的代码，如果修改了的话就把src替换成自己备份的原版代码的地址，这样他在调用的时候就检测不到代码被修改了，不过这种方式现在已和谐。
