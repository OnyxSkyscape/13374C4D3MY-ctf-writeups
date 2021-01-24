from pwn import *

# set up some environmental stuff for pwntools to work properly
context.update(arch='i386', os='linux')
context.terminal = ["termite", "-e"]

p = process("../bin/1337-application")
payload = cyclic(300)

p.sendline(payload)
p.close()