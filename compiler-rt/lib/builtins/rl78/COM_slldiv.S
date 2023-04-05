//===-- COM_slldiv.S - Implement __COM_slldiv-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_slldiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//


  .file  "COM_slldiv.s"

  .text

  .globl  __COM_slldiv
  .type  __COM_slldiv,@function
__COM_slldiv:
  movw  de,ax
  movw  hl,sp
  movw  ax,[hl+12]  ; if (y == 0) then ret = -1
  or  a,x
  or  a,[hl+14]
  or  a,[hl+15]
  or  a,[hl+16]
  or  a,[hl+17]
  or  a,[hl+18]
  or  a,[hl+19]
  bnz  $.L1
  decw  ax
  movw  [de],ax    ; ret = -1
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
.L1:
  clrb  b    ; sign_flag = 0
  mov  a,[sp+11]  ; if (x < 0) then x = -x
  bf  a.7,$.L2
  inc  b    ; sign_flag = 1
  movw  ax,hl
  addw  ax,#4
  movw  hl,ax    ; hl = &x
  call  !!__REL_llrev  ; x = -x
.L2:
  movw  ax,sp
  addw  ax,#12
  movw  hl,ax    ; hl = &y
  mov  a,[sp+19]  ; if (y < 0) then y = -y
  bf  a.7,$.L3
  inc  b    ; sign_flag ^= 1
  call  !!__REL_llrev  ; y = -y
.L3:
  movw  ax,sp
  addw  ax,#4
  xchw  ax,de    ; de = &x, ax = &ret
  push  bc    ; sign_flag
  call  !!__REL_lldiv  ; ret = x / y, hl = &ret
  pop  bc    ; sign_flag
  dec  b
  sknz      ; if (sign_flag == 1) then ret = -ret
  call  !!__REL_llrev  ; ret = -ret
  ret
.Lfunc_end1:
  .size __COM_slldiv, .Lfunc_end1-__COM_slldiv

  .weak  ___divdi3
  .type  ___divdi3,@function
  .set ___divdi3, __COM_slldiv
