//===-- COM_dtoull.S - Implement __fixunsdfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunsdfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dtoull.S"
  .extern __REL_dtoll

  .text

  .globl __COM_dtoull
  .type  __COM_dtoull,@function
__COM_dtoull:
  movw  de,ax
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  mov a,[hl+7]
  bt  a.7,$0f    ; returns zero if the sign is negative
  br  !!__REL_dtoll
0:
  clrw  ax
  movw  [de],ax
  movw  [de+2],ax
  movw  [de+4],ax
  movw  [de+6],ax
  ret
.Lfunc_end1:
  .size __COM_dtoull, .Lfunc_end1-__COM_dtoull

  .weak ___fixunsdfdi
  .type ___fixunsdfdi,@function
  .set  ___fixunsdfdi, __COM_dtoull
