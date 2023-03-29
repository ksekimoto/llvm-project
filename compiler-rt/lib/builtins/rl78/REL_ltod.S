//===-- REL_ltod.S - Implement _REL_ltod-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_ltod for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_ltod.S"

  .text

  .globl __REL_ltod
  .type  __REL_ltod,@function
__REL_ltod:
  xchw  ax,bc

  ;-------------------------------------------------------
  ; check if the input value is 0
  ;-------------------------------------------------------
  addw  ax,bc
  bc  $0f
  bnz $0f    ; if the input value is 0, 0 is returned
  clrw  ax
  movw  [hl],ax   ; substitute 0 for the return value
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  ret
0:
  subw  ax,bc
  
  ;-------------------------------------------------------
  ; find the value of the exponent part
  ; shift left until the most significant bit of bc-ax is set
  ; decrease the value of the exponent part by the number of left shifts
  ;-------------------------------------------------------
  mov d,#31   ; initial value of exponent part (bias value (1023) not added)
  
  cmpw  ax,#0x00    ; is the upper 16 bits 0?
  bnz $1f
  mov a,#16   ; subtract 16 from the value of the exponent
  sub d,a
  clrb  a   ; 16-bit left shift
  xchw  ax,bc
1:
  bt  a.7,$3f  ; (msb == 1)?
2:
  dec d   ; subtract the value of the exponent part
  addw  ax,ax   ; shift the top part to the left
  shlw  bc,1    ; shift lower part to left
  sknc
  incw  ax
  bf  a.7,$2b ; repeat until the most significant bit is raised
3:
  ;-------------------------------------------------------
  ; adjust the bit position according to the format of ieee754
  ;
  ;                     <a>     <x>      <b>      <c>
  ; input value:     1aaaabbb bbbbbccc cccccddd dddddeee
  ;
  ;                   [hl+7]   [hl+6]   [hl+5]   [hl+4]
  ; converted value: seeeeeee eeeeaaaa bbbbbbbb cccccccc
  ;                   [hl+3]   [hl+2]   [hl+1]    [hl]
  ;                  dddddddd eee00000 00000000 00000000
  ;-------------------------------------------------------
  push  ax    ; release the top part
  push  bc    ; release the lower part

  xchw  ax,bc
  shlw  bc,5
  shrw  ax,11
  addw  ax,bc
  movw  [hl+4],ax

  pop ax    ; backward return
  shlw  ax,5
  movw  [hl+2],ax

  clrw  ax
  movw  [hl],ax

  pop ax    ; return to higher rank
  shlw  ax,1    ; remove stingy expressions
  shrw  ax,12
  movw  bc,ax   ; remaining mantissa
  clrb  x
  mov a,d   ; forwarding of exponential part d
  shrw  ax,4
  addw  ax,#0x3ff0  ; bias value addition
  addw  ax,bc   ; mantissa join
  dec e
  sknz      ; negative sign flag
  set1  a.7   ; sign bit
  movw  [hl+6],ax

  ret
.Lfunc_end1:
  .size __REL_ltod, .Lfunc_end1-__REL_ltod
