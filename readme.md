---
title: linux 内核 初探：运行你代码在内核态
categories:
- CTF/Pwn
tags: 
---

> 正向开发是理解一个复杂系统的必要过程，我们熟悉linux用户态的Pwn题，是因为随手就能写出一个helloworld，然后编译、运行、逆向、调试一条龙，进而理解它完整的生命周期。linux内核Pwn的文章有很多，不过大都是以完成一道题目的视角行文的。而本文希望，我们能熟悉内核态的代码的运行状态，具体来说就是：在ubuntu20.04的本机环境下完成 ① 正向开发：将我们的代码送进内核态运行，了解有哪些可以使用的内核函数，基于这些函数我们实现一些功能。② 内存调试：使用log大法对内核态进行调试并分析内存布局。③ 内核本体：找到内核二进制代码本体，认识一下。

## 攻击概述

这并不是我第一次接触内核态代码的运行：

- [Meltdown复现 与 linux检测Meltdown的原理分析](https://xuanxuanblingbling.github.io/ctf/pwn/2020/06/30/meltdown/)
- [HWS夏令营 之 GDB调一切](https://xuanxuanblingbling.github.io/ctf/pwn/2020/08/24/gdb/)
- [HWS 2021 入营赛 Pwn/固件/内核](https://xuanxuanblingbling.github.io/ctf/pwn/2021/02/01/hws/)

基础的内核Pwn题大多是出在外挂的内核模块上，而不是内核本体上，对于内核本体的漏洞研究也接触过一次，但没有调试过：

- [条件竞争学习 之 DirtyCow分析](https://xuanxuanblingbling.github.io/ctf/pwn/2019/11/18/race/)

不过由于内核模块和内核本体处于同一种运行状态，即内核态（x86的ring0，ARM的EL1），所以对二者的攻击效果是一致的，这个层次的最高目标就是拿到内核态的代码执行权限。按照攻击者位置划分，一般有三种攻击入口：

1. 用户态打内核态：接口是所有中断，即引发用户态陷入内核的所有入口，最常见的就是系统调用，系统调用里最常见的就是ioctl，如：许多CTF题目 [Linux Kernel Pwn 初探](https://xz.aliyun.com/t/7625)
2. 从外设打内核态：接口是各种外设的输入，比如空口（wifi、蓝牙等）、线缆（USB、TCP/IP等）、平行系统间（TEE与REE）的通信报文，如：[Bleeding Tooth：Linux蓝牙驱动远程代码执行分析与利用](https://mp.weixin.qq.com/s/rir2GzVBXwh9rWsRFMOzKQ)、[在Tesla Model S上实现Wi-Fi协议栈漏洞的利用](https://mp.weixin.qq.com/s/rULdN3wVKyR3GlGBhunpoQ)、[探索澎湃S1的安全视界](https://vipread.com/library/topic/2929)
3. 更底层控内核态：已经能控了内核态的更底层（x86的ring-1/2/3，ARM的EL2/3），则可直接控制内核态的代码执行，如：[checkra1n](https://checkra.in/releases/)、[checkm30](https://github.com/hhj4ck/checkm30)，注：[负的CPU保护环](https://www.cnblogs.com/liqiuhao/p/9326738.html)

打下内核的代码执行权限后的目标一般有两种：

- 控用户态：对用户态（x86的ring3，ARM的EL0）进行彻底的控制，突破其安全措施（自主访问控制，SELinux等），进而获得用户态的最高权限，这也是最常见的目标。
- 往底层、其他系统打：拿到了通往底层、其他系统的更广阔的接口，如：[利用 ARM 核间调试漏洞获得 SoC 硬件最高权限（上）](https://mp.weixin.qq.com/s/r6xvUzm_x4cJ8jiIasvWmQ)、[利用 ARM 核间调试漏洞获得 SoC 硬件最高权限（下）](https://mp.weixin.qq.com/s/Maq7OufwyJiwZHQHkDy-Jw)

最常见的组合就是：从用户态打内核态，目标是打回到用户态的最高权限。此过程即本地提权：LPE (Local Privilege Escalation)。

更多内容也可以参考ctf-wiki：[https://ctf-wiki.org/pwn/linux/kernel-mode/basic-knowledge/](https://ctf-wiki.org/pwn/linux/kernel-mode/basic-knowledge/)

## 正向开发

### 基础知识

- [https://www.kernel.org/](https://www.kernel.org/)
- [https://www.kernel.org/doc/html/latest/](https://www.kernel.org/doc/html/latest/)


- [linux模块编程（一）—— 加载你的模块](https://blog.csdn.net/qb_2008/article/details/6835677)
- [linux模块编程（二）—— 运行不息的内核线程kthread](https://blog.csdn.net/qb_2008/article/details/6835783)
- [linux模块编程（三）—— 线程的约会completion](https://blog.csdn.net/qb_2008/article/details/6837262)
- [linux模块编程（四）—— 消息的使者list](https://blog.csdn.net/qb_2008/article/details/6839899)
- [linux内核的学习方法](https://blog.csdn.net/qb_2008/article/details/6832361)

### helloworld


```
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ ls
hello.c  Makefile
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ make
make -C /lib/modules/5.8.0-63-generic/build M=/mnt/hgfs/桌面/kernel/hello modules
make[1]: Entering directory '/usr/src/linux-headers-5.8.0-63-generic'
  CC [M]  /mnt/hgfs/桌面/kernel/hello/hello.o
  MODPOST /mnt/hgfs/桌面/kernel/hello/Module.symvers
  CC [M]  /mnt/hgfs/桌面/kernel/hello/hello.mod.o
  LD [M]  /mnt/hgfs/桌面/kernel/hello/hello.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.8.0-63-generic'
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ sudo insmod hello.ko 
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ dmesg | tail -n 1
[ 2009.281102] Hello, world!
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ sudo rmmod hello
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/hello$ dmesg | tail -n 2
[ 2009.281102] Hello, world!
[ 2021.107657] Hello, exit!
```

### watchdog

### 文件读写

- [Linux 内核态文件操作](https://blog.csdn.net/cenziboy/article/details/7867489)



## 内存调试

- [linux 内核调试方法](https://www.cnblogs.com/shineshqw/articles/2359114.html)

### kmem

- [devmem读写物理内存和devkmem读取内核虚拟内存](https://www.cnblogs.com/arnoldlu/p/10721614.html)
- [How to use /dev/kmem?](https://stackoverflow.com/questions/10800884/how-to-use-dev-kmem)
- [https://wiki.ubuntu.com/Security/Features#dev-kmem](https://wiki.ubuntu.com/Security/Features#dev-kmem)


### 自己构建



```
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ sudo insmod ./kmem.ko 
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ cat /proc/kmem 
addr: 0xffffffffad396663 length: 0x20
0F 1F 44 00 00 55 48 89   E5 48 83 EC 50 48 89 74   
24 28 48 89 E6 48 89 54   24 30 48 89 4C 24 38 4C 
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ echo "0xffffffffad396663 0x100" > /proc/kmem
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ cat /proc/kmem 
addr: 0xffffffffad396663 length: 0x100
0F 1F 44 00 00 55 48 89   E5 48 83 EC 50 48 89 74   
24 28 48 89 E6 48 89 54   24 30 48 89 4C 24 38 4C   
89 44 24 40 4C 89 4C 24   48 65 48 8B 04 25 28 00   
00 00 48 89 44 24 18 31   C0 48 8D 45 10 C7 04 24   
08 00 00 00 48 89 44 24   08 48 8D 44 24 20 48 89   
44 24 10 E8 B5 2C 58 FF   48 8B 54 24 18 65 48 33   
14 25 28 00 00 00 74 05   E8 50 42 05 00 C9 C3 65   
48 8B 04 25 C0 7B 01 00   8B 90 18 09 00 00 48 8D   
B0 E8 0A 00 00 48 C7 C7   E0 1F BB AD C6 05 3F A6   
D7 00 01 E8 68 FF FF FF   E9 48 F3 57 FF 48 C7 C7   
A8 20 BB AD 65 48 8B 34   25 C0 7B 01 00 48 81 C6   
E8 0A 00 00 E8 47 FF FF   FF 41 C7 44 24 18 00 00   
00 00 E9 E2 F5 57 FF 55   8B 35 03 32 DC 00 48 C7   
C7 20 93 15 AE 48 89 E5   E8 E0 DA 9E FF 5D C3 0F   
1F 44 00 00 55 48 C7 C0   EA 91 BF AD 48 C7 C6 01   
7E BE AD 48 89 FA 48 89   E5 41 54 F6 47 48 08 49 
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ sudo cat /proc/kallsyms | grep startup_64
ffffffffac800000 T startup_64
ffffffffac800040 T secondary_startup_64
ffffffffac800045 T secondary_startup_64_no_verify
ffffffffac8002f0 T __startup_64
ffffffffac8006d0 T startup_64_setup_env
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ echo "0xffffffffac800000 0x100" > /proc/kmem
xuanxuan@ubuntu:/mnt/hgfs/桌面/kernel/kmem$ cat /proc/kmem 
addr: 0xffffffffac800000 length: 0x100
48 8D 25 51 3F 60 01 48   8D 3D F2 FF FF FF 56 E8   
BC 06 00 00 5E 6A 10 48   8D 05 03 00 00 00 50 48   
CB E8 EA 00 00 00 48 8D   3D D3 FF FF FF 56 E8 BD   
02 00 00 5E 48 05 00 A0   22 2E EB 16 0F 1F 40 00   
E8 CB 00 00 00 56 E8 15   30 00 00 5E 48 05 00 00   
E1 2D B9 A0 00 00 00 F7   05 CF EF 49 01 01 00 00   
00 74 06 81 C9 00 10 00   00 0F 22 E1 48 03 05 9D   
9F 61 01 56 48 89 C7 E8   94 01 00 00 5E 0F 22 D8   
48 C7 C0 89 00 80 AC FF   E0 0F 01 15 70 9F 61 01   
31 C0 8E D8 8E D0 8E C0   8E E0 8E E8 B9 01 01 00   
C0 8B 05 99 27 90 01 8B   15 97 27 90 01 0F 30 48   
8B 25 9A 27 90 01 56 E8   B4 2F 00 00 5E B8 01 00   
00 80 0F A2 89 D7 B9 80   00 00 C0 0F 32 0F BA E8   
00 0F BA E7 14 73 0D 0F   BA E8 0B 48 0F BA 2D DC   
9F 61 01 3F 0F 30 B8 33   00 05 80 0F 22 C0 6A 00   
9D 48 89 F7 68 07 01 80   AC 31 ED 48 8B 05 36 27 
```


- [printk-formats.txt](https://www.kernel.org/doc/Documentation/printk-formats.txt)
- [linux printk](https://lishiwen4.github.io/linux-kernel/printk)


- [获得内核函数地址的四种方法](https://blog.csdn.net/gatieme/article/details/78310036)


## 内核本体

- [Linux升级内核的正确姿势](https://blog.csdn.net/wf19930209/article/details/81879777)


vmlinuz-> vmlinux -> elf 

- [Linux中提取内核vmlinux并转化为带有symbol name的可分析elf](https://blog.csdn.net/qq_40421991/article/details/111241980)
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)
- [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)

- [内核符号表的生成和查找过程](https://blog.csdn.net/jasonchen_gbd/article/details/44025681)