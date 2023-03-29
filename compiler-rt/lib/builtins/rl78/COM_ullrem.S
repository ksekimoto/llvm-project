//===-- COM_ullrem.S - Implement __umoddi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __umoddi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ullrem.S"
  .extern __REL_llrem

  .text

  .globl __COM_ullrem
  .type  __COM_ullrem,@function
__COM_ullrem:
  movw  de,ax
  movw  ax,sp
  addw  ax,#12
  movw  hl,ax   ; hl = &y
  mov a,[hl]    ; if (y == 0) then ret = x
  or  a,[hl+1]
  or  a,[hl+2]
  or  a,[hl+3]
  or  a,[hl+4]
  or  a,[hl+5]
  or  a,[hl+6]
  or  a,[hl+7]
  bnz $0f
  movw  ax,[sp+4] ; ret = x
  movw  [de],ax
  movw  ax,[sp+6]
  movw  [de+2],ax
  movw  ax,[sp+8]
  movw  [de+4],ax
  movw  ax,[sp+10]
  movw  [de+6],ax
  ret
0:
  movw  ax,hl
  subw  ax,#8
  xchw  ax,de   ; de = &x, ax = &ret
  br  !!__REL_llrem ; ret = x % y
.Lfunc_end1:
  .size __COM_ullrem, .Lfunc_end1-__COM_ullrem

  .weak ___umoddi3
  .type ___umoddi3,@function
  .set  ___umoddi3, __COM_ullrem
