# MATRIX Reverse Engineering CTF

## Overview
MATRIX is a reverse engineering challenge from PicoCTF that implements a custom stack-based virtual machine.
The challenge complexity comes from reconstructing program logic executed inside a custom bytecode interpreter.

The goal of this challenge is to reverse engineer the program to navigate through the maze and retrieve the flag.

## VM Architecture

### Instruction Execution
The VM reads a single byte instruction from instructions\[instruction_pointer\], increments the instruction_pointer instruction pointer, and executes the opcode through a switch statement.
```c
opcode = instructions[instruction_pointer];
instruction_pointer++;

switch(opcode) {
    ...
}
```
Ghidra's decompilation of this switch statement was not very helpful, so manually reviewing the main executable's x86 assembly was necessary.
The manual review helped me identify the core design of the VM and assign meaning to the instructions.

### Core Design
* Two stacks for storing data (A and B)
* Stack A is used for arithmetic operations, jump instructions, and IO
* Stack B is used for temporary storage to access values lower in stack A
* 16 bit values are stored on the stack
* Instructions operate on the top of the stack

#### A operations
| Opcode | Description |
|---|---|
|0x10|Duplicate top of A)|
|0x11|Pop from A|
|0x12|Add top two values in A|
|0x13|Subtract top two values in A|
|0x14|Swap top two values on A|

#### Stack transfer
| Opcode | Description |
|---|---|
|0x20|A -> B|
|0x21|B -> A|

#### Control Flow
| Opcode | Description |
|---|---|
|0x00|NOP|
|0x30|JMP|
|0x31|Jump if a.pop() == 0|
|0x32|Jump if a.pop() != 0|
|0x33|Jump if A.pop() < 0|
|0x34|Jump if A.pop() > 0|

#### I/O
| Opcode | Description |
|---|---|
|0xc0|A.push(getc())|
|0xc1|putc(A.pop())|

#### Data Input
| Opcode | Description |
|---|---|
|0x80|Push byte onto A zero extend|
|0x81|Push short onto A|


## Reverse engineering the VM program

### Bytecode Extraction
Given the small instruction set, I was able to implement a custom disassembler to translate raw bytecode into readable pseudo-assembly.  With the Ghidra I could copy the VM bytecode into a python array then process it with **disassemble.py** to get human-readble instructions.
I also implemented a Python-based VM emulator to execute bytecode outside the original binary enabling dynamic analysis.  A 0xaa opcode was also added in my python emulator to dump the stacks for debugging purposes.


With these tools it was possible to reverse engineer the VM logic, find the maze, and solve it.

A snippet from the output.
```
0x000:	a.push(0x75 0x00);
0x003:	a.push(0x00 0x00);
0x005:	a.push(0x0a 0x00);
0x007:	a.push(0x3f 0x00);
0x009:	a.push(0x65 0x00);
0x00b:	a.push(0x76 0x00);
0x00d:	a.push(0x69 0x00);
0x00f:	a.push(0x6c 0x00);
0x011:	a.push(0x61 0x00);
```

### Important Functions

In the pseudo-assembly there were several functions that could be identified through repeated push and goto instructions.

|Address|Name|Description|
|---|---|---|
|0x013b|print_message|pops values off the stack and prints them until reaching 0x0000.|
|0x00fb|you_were_eaten|Push and print the failure message then exit with a fail status.|
|0x0589|success_message|Push and print the success message then exit with a success status.|
|0x007c|next_move|Reads one byte from STDIN, update coordinate variables, and move through the maze. Invalid moves fail the challenge.|
|0x0574|hurt|Decrement the health variable and exits with a fail status if below 0.|
|0x057f|heal|Increment the health variable.|

The next_move function provides the main loop which moves the character through the maze.

While inside this loop the A stack contains the following variables in this order
```
	x
	y
	health
```

Snippets from each function
```c
print_message() {
	0x13b:	a.push(a.peek());
	0x13c:	a.push(0x45 0x01);
	0x13f:	tmp = a.pop(); if(a.pop() == 0) goto tmp; //goto 0x145 at the end
	0x140:	putc(a.pop(), stdout);
	0x141:	a.push(0x3b 0x01);
	0x144:	goto a.pop();
}

next_move() {
	0x07c:	a.push(a.peek());
	0x07d:	a.push(0x75 0x00);
	0x07f:	a.push(-a.pop() + a.pop());
    ...
	
	0x0a0:	a.pop();	//	u
	0x0a1:	b.push(a.pop());
	0x0a2:	a.push(0x01 0x00);
	0x0a4:	a.push(-a.pop() + a.pop());
	0x0a5:	a.push(b.pop());
	0x0a6:	a.push(0xcc 0x00);
	0x0a9:	goto a.pop();
    ...
}

you_were_eaten() {
	0x0fb:	a.push(0x38 0x01);
	0x0fe:	a.push(0x00 0x00);
    ...
	0x132:	a.push(0x59 0x00);
	0x134:	a.push(0x3b 0x01);
	print_message()
	0x137:	goto a.pop();
}

success_message() {
	0x589:	a.push(0xce 0x05);
	0x58c:	a.push(0x00 0x00);
    ...
	0x5c8:	a.push(0x43 0x00);
	0x5ca:	a.push(0x3b 0x01);
	0x5cd:	goto a.pop();
}

hurt() {
	0x574:	b.push(a.pop());
	0x575:	a.push(a.peek());
	0x576:	a.push(0xfb 0x00);
	0x579:	tmp = a.pop(); if(a.pop() == 0) goto tmp;
	0x57a:	a.push(0x01 0x00);
	0x57c:	a.push(-a.pop() + a.pop());
	0x57d:	a.push(b.pop());
	0x57e:	goto a.pop();
}

heal() {
	0x57f:	b.push(a.pop());
	0x580:	a.push(0x01 0x00);
	0x582:	a.push(a.pop() + a.pop());
	0x583:	a.push(b.pop());
	0x584:	goto a.pop();
	0x585:	a.pop();
	0x586:	a.pop();
	0x587:	a.pop();
	0x588:	a.pop();
}
```

## Program Behavior

### Intro Message
The challenge starts by pushing an intro message onto A then printing it out.
The print function pops values off A until you reach a null value then it returns.

### User input
After printing out the intro message the main loop is entered.  Here bytes are are read from STDIN using getc.  The accepted inputs are 'u', 'd', 'l', and 'r'.  Anything else will fail the challenge.

```c
if(input == 'u') y -= 1;
if(input == 'd') y += 1;
if(input == 'l') x -= 1;
if(input == 'r') x += 1; 
```

### Maze Indexing
The maze is a set of instructions located at the end of the VM instructions and jumped into using two variables.  This segment identifes both the x and y variables.
The logic for jumping into the maze is spread out across the VM instructions but the net result is below.
```
offset = 0x10 * y + x;
destination = base + 4*index;
goto destination;
```

This shows that the maze is encoded as a jump table where each location corresponds to a 4-byte instruction block with 16 blocks wide rows.

### The Maze
Analysis of the jump table region reveals repeating instruction patterns.  These patterns jump execution into different segments of the code which can be reversed engineed into identifiable functions and provide meaning to each block.

At this step I identified the hurt and heal function which gave meaning to the final health variable.

##### Safe Tiles
Safe tiles are always safe to walk on.  This takes you back to the next_move function
```
goto a.pop(); next_move()
NOP;
NOP;
NOP;
```

##### Walls
Walls always result in failure.
Failures are met with a "You were eaten by a grue." message
```
a.push(0xfb 0x00);
goto a.pop(); you_were_eaten()
```

##### Traps
Traps decrease health by 1.  If health goes below 0 you lose.
```
a.push(0x74 0x05);
goto a.pop(); hurt()

```

##### Heal Tiles
Heal Tiles increase health by 1.
```
a.push(0x7f 0x05);
goto a.pop(); heal()
```

##### Exit
The exit prints a success message.
```
a.push(0x89, 0x05);
goto a.pop(); success_message()
```
##### Drawing the Maze

By replacing the patterns with some symbols and organizing them into a 16 wide grid the maze can be reconstructed.

|Symbol|Tile|
|---|---|
|X|Wall|
|S|Start|
|.|Safe|
|?|Healing|
|!|Trap|
|E|Exit|

```
X X X X X X X X X X X X X X X X
X S . . . . ? X . X ? . . X . X
X X X X ! X X X . X X X . X . X
X . . . . . . . . . . X . X . X
X X . X . X X X X X . X . ! . X
X . . X . X ? . . X . X . X . X
X . X X . X X X . X . X . X . X
X . X . . . . . . X . X . X . X
X . X . X X X X X X . X . X . X
X . X . . . . . . . . X . X . X
X . X X X . X X X X X X . X . X
X . . . X . . ! . . X . . X . X
X . X X X . . X . . X . X . . X
X . X . . . X X X . X . X ! X X
X . X . . . . X . . ! . X . . X
X X X X X X X X X X X X X X G X
```

Upon reaching the exit control is returned from the VM to the main program and the flag is retrieved.

## Result

By reconstructing the VM instruction set, control flow, and jump table layout, I was able to:

- Identify the maze structure encoded in bytecode
- Track player state (x, y, health) through stack operations
- Determine valid movement sequences
- Successfully reach the goal state and recover the flag


## Tooling
- **disassemble.py** converts the raw VM instructions into human readable pseudo-assembly.
- **vm.py** is available to emulate the custom architecture and run the challenge or any custom programs.