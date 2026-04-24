# CTF Challenges

## MATRIX
- Reconstructed the architecture and instruction set of a custom stack-based virtual machine
- Analyzed control flow and execution model to solve the embedded program

## Homework
- Reverse engineered a custom Befunge-like 2D stack-based virtual machine
- Exploited an off-by-one bounds check to achieve out-of-bounds memory access
- Corrupted VM metadata to bypass memory constraints and enable arbitrary memory traversal
- Implemented a loop to leak memory and recover the flag

## Filtered Shellcode
- Developed shellcode resilient to transformation filters
- Crafted payloads under strict byte-level constraints to preserve execution
- Identified and exploited a secondary vulnerability for an alternate solution path

## ROP Exploitation (ropfu)
- Built a return-oriented programming (ROP) chain to achieve arbitrary code execution
- Optimized payload size while maintaining exploit reliability


## Tools & Technologies

- Ghidra
- GDB / pwndbg
- Python / pwntools
- x86 / x86-64 Assembly
