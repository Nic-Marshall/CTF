#!/usr/bin/python
import numpy as np
import random

# np will throw a lot of overflow errors without this
np.seterr(over="ignore")

def toint(bytes):
  return int.from_bytes(bytes, byteorder="little", signed=False)

# Return the hex string for the two's complement of an integer to verify it maches the QEMU output
def twoc(num):
  return hex(num & ((1<<32) - 1))

# Run the encoding process forwards given user inputs reg0 - reg5
def run_vm(reg0=b'\x11\x11\x11\x11', reg1=b'\x22\x22\x22\x22', reg2=b'\x33\x33\x33\x33',
  reg3=b'\x44\x44\x44\x44', reg4=b'\x55\x55\x55\x55', reg5=b'\x66\x66\x66\x66'):
  # Initialize
  reg = np.array([0]*20, dtype="uint32")
  
  # User Input
  reg[0] = toint(reg0)
  reg[1] = toint(reg1)
  reg[2] = toint(reg2)
  reg[3] = toint(reg3)
  reg[4] = toint(reg4)
  reg[5] = toint(reg5)
  
  # Pre-Determined registers
  reg[6]  = toint(b'\x20\x37\xef\xc6')
  reg[7]  = toint(b'\xb9\x79\x37\x9e')
  reg[13] = toint(b'\x20\x00\x00\x00')
  
  while reg[8] != reg[13]:
    reg[9]  = reg[0] >> 0x05
    reg[9]  = reg[9] + reg[5]
    reg[10] = reg[0] + reg[6]
    reg[11] = reg[0] << 0x04
    reg[11] = reg[11] + reg[4]
    reg[12] = reg[11] ^ reg[10]
    reg[12] = reg[12] ^ reg[9]
    reg[1]  = reg[1] - reg[12]
  
    reg[9]  = reg[1] >> 0x05
    reg[9]  = reg[9] + reg[3]
    reg[10] = reg[1] + reg[6]
    reg[11] = reg[1] << 0x04
    reg[11] = reg[11] + reg[2]
    reg[12] = reg[11] ^ reg[10]
    reg[12] = reg[12] ^ reg[9]
    reg[0]  = reg[0] - reg[12]
  
    reg[14] = 0x00000001
    reg[8]  = reg[8] + reg[14]
    reg[6]  = reg[6] - reg[7]
  
  print(f"[ {", ".join([twoc(i) for i in reg])} ]")

# Run the encoding process backwards given reg0 and reg1 match the goal and user provided reg2 - reg5
def run_backwards(reg2=b'\x33\x33\x33\x33', reg3=b'\x44\x44\x44\x44',
  reg4=b'\x55\x55\x55\x55', reg5=b'\x66\x66\x66\x66'):
  # Initialize
  reg = np.array([0]*20, dtype="uint32")
  
  # Goal
  reg[0] = toint(b'\xfe\xaa\x01\xba')
  reg[1] = toint(b'\xa3\x31\xff\xbb')

  # User Input
  reg[2] = toint(reg2)
  reg[3] = toint(reg3)
  reg[4] = toint(reg4)
  reg[5] = toint(reg5)
  
  # Pre-Determined things
  reg[6]  = toint(b'\x00\x00\x00\x00')
  reg[7]  = toint(b'\xb9\x79\x37\x9e')
  reg[8]  = toint(b'\x20\x00\x00\x00')
  reg[13] = toint(b'\x20\x00\x00\x00')
  reg[14] = toint(b'\x01\x00\x00\x00')
  
  while reg[8] != 0x00000000:
    reg[6] = reg[6] + reg[7]
    reg[8] = reg[8] - reg[14]
    reg[14] = 0x00000001

    reg[9]  = reg[1] >> 0x05
    reg[9]  = reg[9] + reg[3]
    reg[10] = reg[1] + reg[6]
    reg[11] = reg[1] << 0x04
    reg[11] = reg[11] + reg[2]
    reg[12] = reg[11] ^ reg[10]
    reg[12] = reg[12] ^ reg[9]
    reg[0]  = reg[0] + reg[12]

    reg[9]  = reg[0] >> 0x05
    reg[9]  = reg[9] + reg[5]
    reg[10] = reg[0] + reg[6]
    reg[11] = reg[0] << 0x04
    reg[11] = reg[11] + reg[4]
    reg[12] = reg[11] ^ reg[10]
    reg[12] = reg[12] ^ reg[9]
    reg[1]  = reg[1] + reg[12]
  
  print(f"[ {", ".join([twoc(i) for i in reg])} ]")
  print(f"Copyable-Key:\n{",".join([twoc(i).replace("0x","") for i in reg[0:6]])}")
  return reg[0:2]


if __name__=="__main__":
  reg2, reg3, reg4, reg5 = [random.randint(0, 2**32-1).to_bytes(4) for i in range(4)]
  reg0,reg1 = run_backwards(reg2, reg3, reg4, reg5)
  run_vm(reg0,reg1)
