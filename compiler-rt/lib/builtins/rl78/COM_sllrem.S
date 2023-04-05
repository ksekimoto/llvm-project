//===-- COM_sllrem.S - Implement __moddi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __moddi3 for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_sllrem.S"
  .extern __REL_llrem
  .extern __REL_llrev

  .text

  .globl __COM_sllrem
  .type  __COM_sllrem,@function
__COM_sllrem:
  movw  de,ax
  movw  hl,sp
  mov a,[hl+12] ; if (y == 0) then ret = x
  or  a,[hl+13]
  or  a,[hl+14]
  or  a,[hl+15]
  or  a,[hl+16]
  or  a,[hl+17]
  or  a,[hl+18]
  or  a,[hl+19]
  bnz $0f
  movw  ax,[hl+4] ; ret = x
  movw  [de],ax
  movw  ax,[hl+6]
  movw  [de+2],ax
  movw  ax,[hl+8]
  movw  [de+4],ax
  movw  ax,[hl+10]
  movw  [de+6],ax
  ret
0:
  clrb  b   ; sign_flag = 0
  mov a,[sp+11] ; if (x < 0) then x = -x
  bf  a.7,$1f
  inc b   ; sign_flag = 1
  movw  ax,hl
  addw  ax,#4
  movw  hl,ax   ; hl = &x
  call  !!__REL_llrev ; x = -x
1:
  movw  ax,sp
  addw  ax,#12
  movw  hl,ax   ; hl = &y
  mov a,[sp+19] ; if (y < 0) then y = -y
  bf  a.7,$2f
  call  !!__REL_llrev ; y = -y
2:
  movw  ax,sp
  addw  ax,#4
  xchw  ax,de   ; de = &x, ax = &ret
  push  bc    ; sign_flag
  call  !!__REL_llrem ; ret = x % y, hl = &ret
  pop bc    ; sign_flag
  dec b
  sknz      ; if (sign_flag == 1) then ret = -ret
  call  !!__REL_llrev ; ret = -ret
  ret
.Lfunc_end1:
  .size __COM_sllrem, .Lfunc_end1-__COM_sllrem

  .weak ___moddi3
  .type ___moddi3,@function
  .set  ___moddi3, __COM_sllrem
