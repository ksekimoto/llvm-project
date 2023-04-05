//===-- COM_ftosll.S - Implement __fixsfdi-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __fixsfdi for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ftosll.S"
  .extern __REL_ftoll
  .extern __REL_lltosll

  .text

  .globl __COM_ftosll
  .type  __COM_ftosll,@function
__COM_ftosll:
  movw  hl,ax
  push  hl
  call  !!__REL_ftoll
  pop hl
  br  !!__REL_lltosll
.Lfunc_end1:
  .size __COM_ftosll, .Lfunc_end1-__COM_ftosll

  .weak ___fixsfdi
  .type ___fixsfdi,@function
  .set  ___fixsfdi, __COM_ftosll
