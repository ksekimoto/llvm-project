//===-- COM_ulldiv.S - Implement __udivdi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __udivdi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ulldiv.S"
  .extern __REL_lldiv

  .text

  .globl __COM_ulldiv
  .type  __COM_ulldiv,@function
__COM_ulldiv:
  movw  de,ax
  movw  ax,sp
  addw  ax,#12
  movw  hl,ax   ; hl = &y
  movw  ax,[hl]   ; if (y == 0) then ret = -1
  or  a,x
  or  a,[hl+2]
  or  a,[hl+3]
  or  a,[hl+4]
  or  a,[hl+5]
  or  a,[hl+6]
  or  a,[hl+7]
  bnz $0f
  decw  ax
  movw  [de],ax   ; ret = -1
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
0:
  movw  ax,hl
  subw  ax,#8
  xchw  ax,de   ; de = &x, ax = &ret
  br  !!__REL_lldiv ; ret = x / y
.Lfunc_end1:
  .size __COM_ulldiv, .Lfunc_end1-__COM_ulldiv

  .weak ___udivdi3
  .type ___udivdi3,@function
  .set  ___udivdi3, __COM_ulldiv
