//===-- COM_dtosll.S - Implement __fixdfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixdfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_dtosll.S"
  .extern __REL_dtoll
  .extern __REL_lltosll

  .text

  .globl __COM_dtosll
  .type  __COM_dtosll,@function
__COM_dtosll:
  push  ax
  movw  de,ax
  movw  ax,sp
  addw  ax,#6
  movw  hl,ax
  call  !!__REL_dtoll
  pop hl      ; return address
  br  !!__REL_lltosll
.Lfunc_end1:
  .size __COM_dtosll, .Lfunc_end1-__COM_dtosll

  .weak ___fixdfdi
  .type ___fixdfdi,@function
  .set  ___fixdfdi, __COM_dtosll
