# arm_kgme1 Reverse Engineering CTF

## Overview

arm_kgme1 is a reverse engineering challenge from crackmes.one [arm_kgme1](https://crackmes.one/crackme/5ab77f5d33c5d40ad448c69c) by esteve. It is a 32-bit ARM ELF that implements a small
register-based virtual machine. The VM program is stored in the binary as fake ARM instructions placed right after `main()`, and
it is read through `$lr` from the call to `interpret_vm()` from main.

The user enters six 32-bit integers. They are loaded into VM registers 0 through 5, the VM program runs, and the program accepts
the input only if two comparisons succeed. The challenge complexity comes from recognizing that the VM program is a block cipher
(TEA) and working out what inputs make its output match a fixed target.

### Running and debugging

```
qemu-arm -L /usr/arm-linux-gnueabi/ ./arm_kgme1

qemu-arm -g 1234 -L /usr/arm-linux-gnueabi/ ./arm_kgme1
gdb-multiarch ./arm_kgme1
(gdb) set arch arm
(gdb) target remote localhost:1234
```

## VM Architecture

### Instruction Execution

The VM fetches a 32-bit instruction from the instruction pointer, uses the low byte as an index into a table of handler functions,
and calls the handler with the three argument bytes.

```c
do {
    instruction = *regs->instruction_pointer;              // regs + 0x7c
    handler = vm->opcode_functions[instruction.opcode];    // low byte, 4-byte table entries
    handler(instruction.arg0, instruction.arg1, instruction.arg2, vm, machine_code);
} while (regs->instruction_pointer != endpoint);
```

On ARM, each handler receives `r0 = arg0`, `r1 = arg1`, `r2 = arg2`, and `r3 = &vm`.

### Core Design

* Fixed-width 32-bit instructions: byte 0 is the opcode, bytes 1 to 3 are `arg0`, `arg1`, `arg2`
* A register block of 0x80 bytes: 32-bit registers, then `stack_pointer` at +0x78 and `instruction_pointer` at +0x7c
* A 400-byte stack buffer
* A second, smaller buffer `flags` used for flags. Most handlers never touch it
* Register 0 to 5 hold the user input

```c
struct vm_instruction {
    uint8_t opcode;
    uint8_t arg0;
    uint8_t arg1;
    uint8_t arg2;
};

struct vm_registers {
    int registers[30];
    int *stack_pointer;
    vm_instruction *instruction_pointer;
};

struct vm_struct {
    vm_registers *register_data;
    int program_length;
    void *stack;
    void *flags;
    void **opcode_functions;
};
```

#### Instruction set

Eleven opcodes are used by this program.

| Opcode | Name | Description |
|---|---|---|
|0x00|concat_0021|`reg[arg0]` low 16 bits = `arg2 << 8 \| arg1`, high 16 bits kept|
|0x01|concat_1200|`reg[arg0]` high 16 bits = `arg1 << 8 \| arg2`, low 16 bits kept|
|0x02|add|`reg[arg0] = reg[arg1] + reg[arg2]`|
|0x03|jump|Relative jump of a signed 16-bit count of instructions, `arg1 << 8 \| arg2`. `arg0` selects the `flags` flag to test|
|0x04|compare|`flags[1] = (reg[arg0] == reg[arg1])`|
|0x05|push|Push `reg[arg0]` onto the stack|
|0x06|pop|Pop the stack into `reg[arg0]`|
|0x07|sub|`reg[arg0] = reg[arg1] - reg[arg2]`|
|0x08|bitshift|Shift `reg[arg0]` by `arg1` bits: right if `arg2 == 1`, otherwise left|
|0x09|xor|`reg[arg0] = reg[arg1] ^ reg[arg2]`|
|0x63|nop|No operation|

The names are labels I assigned; the binary has none. The two `concat` opcodes are the only way to build a constant, so each 32-bit value takes two
instructions: one for the low half and one for the high half.

The program also uses `push` followed by `pop` as a register-to-register copy, because the arithmetic opcodes work in place on
`arg0`. For example `push 00` then `pop 09` copies `reg0` into `reg9`.

## Reverse engineering the VM program

### Bytecode Extraction

The program is 50 instruction words. I copied them out of Ghidra and decoded each one against the handler table, which produced
the listing below.

```
37200600 79b90700 efc60601 379e0701 01000005 01010906 ...
```

### Annotated program

Setup: build the two constants.

```
concat_0021 06, 20, 37     ; reg6 = 0x????3720
concat_0021 07, b9, 79     ; reg7 = 0x????79b9
concat_1200 06, c6, ef     ; reg6 = 0xc6ef3720
concat_1200 07, 9e, 37     ; reg7 = 0x9e3779b9
```

One round (label JMP0). The first half updates `reg1` using `reg0`:

```
push 00 / pop 09 / bitshift 09, 05, 01     ; reg9  = reg0 >> 5
add  09, 09, 05                             ; reg9  = reg9 + reg5
add  0a, 00, 06                             ; reg10 = reg0 + reg6
push 00 / pop 0b / bitshift 0b, 04, 00     ; reg11 = reg0 << 4
add  0b, 0b, 04                             ; reg11 = reg11 + reg4
xor  0c, 0b, 0a                             ; reg12 = reg11 ^ reg10
xor  0c, 0c, 09                             ; reg12 = reg12 ^ reg9
sub  01, 01, 0c                             ; reg1  = reg1 - reg12
```

The second half does the same for `reg0` using the new `reg1`, with `reg3` and `reg2` as the added key words:

```
push 01 / pop 09 / bitshift 09, 05, 01     ; reg9  = reg1 >> 5
add  09, 09, 03                             ; reg9  = reg9 + reg3
add  0a, 01, 06                             ; reg10 = reg1 + reg6
push 01 / pop 0b / bitshift 0b, 04, 00     ; reg11 = reg1 << 4
add  0b, 0b, 02                             ; reg11 = reg11 + reg2
xor  0c, 0b, 0a ; xor 0c, 0c, 09           ; reg12 = reg11 ^ reg10 ^ reg9
sub  00, 00, 0c                             ; reg0  = reg0 - reg12
```

Loop control:

```
concat_0021 0e, 01, 00 ; concat_1200 0e, 00, 00   ; reg14 = 1
add     08, 08, 0e                                 ; reg8 = reg8 + 1
compare 08, 0d, 01                                 ; flag = (reg8 == reg13), reg13 = 0x20
sub     06, 06, 07                                 ; reg6 = reg6 - reg7
jump    81, ff, e3                                 ; 0xffe3 = -29: back to JMP0 while the flag is 0
```

Final checks:

```
concat_0021 02, fe, aa ; concat_1200 02, ba, 01   ; reg2 = 0xba01aafe
concat_0021 03, a3, 31 ; concat_1200 03, bb, ff   ; reg3 = 0xbbff31a3
compare 02, 00, 00                                 ; flag = (reg2 == reg0)
jump    81, 00, 03                                 ; skip the next two instructions unless equal
concat_0021 00, 01, 00 ; concat_1200 00, 00, 00   ; reg0 = 1
compare 03, 01, 01                                 ; flag = (reg3 == reg1)
jump    81, 00, 03                                 ; skip the next two instructions unless equal
concat_0021 01, 01, 00 ; concat_1200 01, 00, 00   ; reg1 = 1
nop x4
```

## What the VM computes

The loop runs 32 times, with `reg6` starting at 0xc6ef3720 and dropping by 0x9e3779b9 each round. The constant 0x9e3779b9 is the
TEA delta (2^32 divided by the golden ratio), and 0xc6ef3720 is 32 times delta, which is the sum value at the start of a 32-round
TEA **decryption**. The round function matches TEA, not XTEA: the four key words are added directly into the shifted terms instead of
being picked by `sum & 3` and `(sum >> 11) & 3`.

```c
// v0 = reg0, v1 = reg1, key = { reg2, reg3, reg4, reg5 }, sum = 0xc6ef3720
for (i = 0; i < 32; i++) {
    v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);   // k2 = reg4, k3 = reg5
    v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);   // k0 = reg2, k1 = reg3
    sum -= 0x9e3779b9;
}
```

After the loop the program replaces `reg2` and `reg3` with the target block, 0xba01aafe and 0xbbff31a3, and compares them with the
decrypted `reg0` and `reg1`. Each match sets that register to 1.

So the VM decrypts the 64-bit block `(reg0, reg1)` with the 128-bit key `(reg2, reg3, reg4, reg5)` and accepts it if the plaintext
is exactly `0xba01aafe, 0xbbff31a3`.

## Solving

The key is free. For any four key words there is exactly one `(reg0, reg1)` that decrypts to the target, so the challenge has
2^128 valid inputs and works as a keygen. To produce one, pick random key words and **encrypt** the target block with TEA, which runs
the same rounds in the opposite direction:

```c
sum = 0;
for (i = 0; i < 32; i++) {
    sum += 0x9e3779b9;
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
}
```

with `v0 = 0xba01aafe` and `v1 = 0xbbff31a3` going in, and `reg2` to `reg5` as `k0` to `k3`. The result is the `reg0` and `reg1` to
enter. For example, key words `0x11111111, 0x22222222, 0x33333333, 0x44444444` give `reg0 = 0x2213aa7e` and `reg1 = 0x231c4313`.

The script prints a ready-to-copy line of the six values. `2213aa7e,231c4313,11111111,22222222,33333333,44444444`

### Verification

32-bit wraparound is the main source of mistakes in a Python version, so the script uses NumPy `uint32`, and `twoc()` prints each
register as an unsigned 32-bit hex value so it can be compared directly with the QEMU and gdb output. The keygen's output was also
checked against a separate plain-Python TEA implementation, and the forward model (`run_vm`) recovers the target block for the
generated keys.

## Result

By decoding the VM instruction set and annotating the program, I was able to:

- Identify the VM program as a 32-round TEA decryption with a fixed target block
- Map `reg2` to `reg5` to the four key words and `reg0`, `reg1` to the data block
- Invert the check by encrypting the target instead of searching for it
- Generate valid inputs for any chosen key

## Tooling

- **keygen.py** models the VM forwards (`run_vm`) and generates valid inputs backwards (`run_backwards`). It needs Python 3.12 or newer and NumPy.
