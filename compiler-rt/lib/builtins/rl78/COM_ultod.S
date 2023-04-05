//===-- COM_ultod.S - Implement __floatunsidf-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __floatunsidf for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_ultod.S"
  .extern __REL_ltod

  .text

  .globl __COM_ultod
  .type  __COM_ultod,@function
__COM_ultod:
  movw  hl,ax   ; store the return address in the hl register
  movw  ax,de
  mov e,#0    ; store sign (always positive)

  xchw  ax,bc
  br  !!__REL_ltod
.Lfunc_end1:
  .size __COM_ultod, .Lfunc_end1-__COM_ultod

  .weak ___floatunsidf
  .type ___floatunsidf,@function
  .set  ___floatunsidf, __COM_ultod
