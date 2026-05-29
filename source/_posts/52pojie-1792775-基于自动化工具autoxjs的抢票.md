---
title: 基于自动化工具autoxjs的抢票
date: 2025-01-01 00:00:00
tags:
  - AutoXjs
  - Java
  - Root
  - 算法分析
categories:
  - 编程开发
description: "**0x00 前情提要** 
 之前看到有大佬发了某麦网的apk加密接口分析那篇帖子，其中提到了用自动化工具开发出来的效果不太好，但是感觉自动化的不应该这么慢，于是尝试用autoxjs实现一个基于自动化的抢票工具，之前还用这个做过一个定时打卡的脚本，有需要的话我也可以分享一下。 
 **0x01 环境** 
 windows 10一加真机，Android11x麦apk 版本8.5.4adb 33."
---

### 0x00 前情提要

之前看到有大佬发了某麦网的apk加密接口分析那篇帖子，其中提到了用自动化工具开发出来的效果不太好，但是感觉自动化的不应该这么慢，于是尝试用autoxjs实现一个基于自动化的抢票工具，之前还用这个做过一个定时打卡的脚本，有需要的话我也可以分享一下。

### 0x01 环境

windows 10一加真机，Android11x麦apk 版本8.5.4adb 33.0.0autoxjsscrcpy（可以把真机上的画面投射到电脑上，并且在电脑上操作手机）VScode(安装autoxjs的插件可以方便通过电脑在手机上进行测试和开发，可用可不用)

### 0x02 环境搭建

**autoxjs环境搭建**

原本的autojs作者已经不再维护了，autoxjs是民间维护版本，目前选择autoxjs。安装autox.js的apk，打开app

![](https://attach.52pojie.cn/forum/202306/02/150026e16rafwsc3cc93rs.png)

按上图设置好之后，如果你的设备有root的话点击设置，打开使用root权限自动启用服务，不然每次重启app都需要手动打开一次无障碍服务，不过好像有能通过脚本打开无障碍服务的方法，这个有兴趣的可以自己去找一下

![](https://attach.52pojie.cn/forum/202306/02/150030uf1bbblxtae488xy.png)

**VScode环境搭建**

官网上下载vscode，在插件商店里搜autoxjs，安装插件

![](https://attach.52pojie.cn/forum/202306/02/150032wupo3ppli272uulq.png)

安装好后打开手机上的Autoxjs，打开“打开USB调试”

在电脑上的VScode里按Ctrl+Shift+p，点击开启服务并监听ADB设备

![](https://attach.52pojie.cn/forum/202306/02/150035ty5fxxz3ffdjfdf0.png)

成功开启后，手机上autoxjs中连接电脑选项会自动开启

![](https://attach.52pojie.cn/forum/202306/02/150040vp4274bq35a4ytdd.png)

至此前期准备工作大概就做好了。

### 0x03 分析app

在这里打开悬浮窗，开启成功后会在屏幕左边出现一个小的悬浮窗图标

打开dm app，在这个页面点击autoxjs悬浮窗图标，再点击从上到下数第三个图标（蓝色），

![](https://attach.52pojie.cn/forum/202306/02/151257yv4wj3363tvxuwcr.png)

有两个选项：布局范围分析、布局层次分析，选布局范围分析

![](https://attach.52pojie.cn/forum/202306/02/151457osejv4lgzt8ldf7s.png)

再当前页面点击控件就能获取到控件的信息

![](https://attach.52pojie.cn/forum/202306/02/151920gid8ll7sr88hr9lc.png)

接着就是对页面进行分析，然后根据流程一个个去判断页面和判断、点击按钮

大概的代码如下所示

```javascript
function damai() {

 //五月天测试

 var date = ["05-31", "06-01", "06-03"];

 var prices = ["1555", "355", "1855", "555", "855", "1655"];

 var viewer = ["111","zzz"];

 

 var flag = true;

 console.log("开始执行");

 while (!id("tv_price_name").className("android.widget.TextView").textContains("票档").exists()) {

 click("立即");

 }

 console.log(1);

 while (true) {

 for (var j = 0; j < date.length; j++) {

 //场次缺票判断

 if (textContains(date[j]).findOne(0).parent().child(1).child(0) != null && textContains(date[j]).findOne(0).parent().child(1).child(0).text() == "无票")

 continue;

 //选择场次

 clickMessage(date[j]);

 //选择未缺货价格

 for (var i = 0; i < prices.length; i++) {

 var price = textContains(prices[i]).findOne(0);

 if (price.parent().child(1).child(0) != null) {

 console.log(price.text() + " " + "缺货登记");

 continue;

 }

 clickMessage(price.text());

 var plus = textContains("1张").findOne(0).parent().child(2);

 for (var i = 0; i < viewer.length - 1; i++) {

 plus.click();

 }

 if (!click("确定")) {

 console.log("fake");

 var clickButton = textContains("确定").findOne(0).parent();

 clickButton.click();

 }

 console.log(price.text());

 break;

 }

 for (var k = 0; k < viewer.length; k++) {

 console.log(viewer[k]);

 console.log(k);

 if(textContains(viewer[k]).exists())

 textContains(viewer[k]).findOne(0).parent().child(3).click();

 }

 clickMessage("提交订单");

 clickMessage("我知道了")

 if(id("damai_theme_dialog_confirm_btn").className("android.widget.TextView").text("我知道了").exists()) {

 click("我知道了");

 }

 }

 }

}
```

```javascript
//根据控件文字点击

function clickMessage(message) {

 if (!click(message)) {

 console.error("点击" + message + "出错");

 }

}
```

从订单详情页面到提交订单页面的时间（包括勾选多张票和多个观影人）大概需要0.5秒，这种方法是比人手抢要快的，但是肯定没有那位大佬通过发包的方式抢的快，而且稳定性方面还待确认。

![](https://attach.52pojie.cn/forum/202306/02/164516ztk7cob71jahtlm7.png)

### 0x04 小结

本人也是这方面的新手，这个脚本本身算法和实现还有一些可以优化的地方，仅供大家参考，用自动化工具的优势算是比较好做各个app和机型的适配。还有一些人会遇到滑动条验证的问题（我本人还没遇到过），autoxjs提供了opencv的库可以用这个先识别滑块位置然后调用滑动事件，网上也有很多种解决方案，但是autoxjs使用无障碍的方式有时候会无法滑动滑动块，可能需要自己调用系统的api去写一个滑动事件。
