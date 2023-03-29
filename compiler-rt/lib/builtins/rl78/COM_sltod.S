//===-- COM_sltod.S - Implement __floatsidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatsidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_sltod.S"
  .extern __REL_ltod

  .text

  .globl __COM_sltod
  .type  __COM_sltod,@function
__COM_sltod:
  movw  hl,ax   ; store the return address in the hl register
  movw  ax,de

  mov e,#0    ; store sign (positive)
  mov1  cy,a.7
  bnc $0f    ; if the sign bit is 0 (positive), no sign conversion is performed

  ; sign inversion
  movw  de,ax
  clrw  ax
  subw  ax,bc
  movw  bc,ax
  subc  a,a
  mov x,a
  subw  ax,de
  
  mov e,#1    ; store sign (negative)
0:
  xchw  ax,bc
  br  !!__REL_ltod
.Lfunc_end1:
  .size __COM_sltod, .Lfunc_end1-__COM_sltod

  .weak ___floatsidf
  .type ___floatsidf,@function
  .set  ___floatsidf, __COM_sltod
