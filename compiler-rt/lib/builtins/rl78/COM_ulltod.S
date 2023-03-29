//===-- COM_ulltod.S - Implement __floatundidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatundidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ulltod.S"
  .extern __REL_lltod

  .text

  .globl __COM_ulltod
  .type  __COM_ulltod,@function
__COM_ulltod:
  clrb  b   ; store sign (always positive)
  movw  de,ax
  movw  ax,sp
  addw  ax,#4
  movw  hl,ax
  br  !!__REL_lltod
.Lfunc_end1:
  .size __COM_ulltod, .Lfunc_end1-__COM_ulltod

  .weak ___floatundidf
  .type ___floatundidf,@function
  .set  ___floatundidf, __COM_ulltod
