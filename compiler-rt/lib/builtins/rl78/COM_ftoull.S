//===-- COM_ftoull.S - Implement __fixunssfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixunssfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ftoull.S"
  .extern __REL_ftoll

  .text

  .globl __COM_ftoull
  .type  __COM_ftoull,@function
__COM_ftoull:
  movw  hl,ax
  mov a,d
  bt  a.7,$0f    ; returns zero if the sign is negative
  br  !!__REL_ftoll
0:
  clrw  ax
  movw  [hl],ax
  movw  [hl+2],ax
  movw  [hl+4],ax
  movw  [hl+6],ax
  ret
.Lfunc_end1:
  .size __COM_ftoull, .Lfunc_end1-__COM_ftoull

  .weak ___fixunssfdi
  .type ___fixunssfdi,@function
  .set  ___fixunssfdi, __COM_ftoull
