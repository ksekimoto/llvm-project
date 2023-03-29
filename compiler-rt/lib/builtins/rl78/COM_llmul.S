//===-- COM_llmul.S - Implement __muldi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __muldi3 for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "COM_llmul.S"
  .extern __REL_llmul_addh
  .extern __COM_mulul
  .extern __COM_lmul

  .text

  .globl __COM_llmul
  .type  __COM_llmul,@function
__COM_llmul:
  push  ax      ; return address
  movw  ax,[sp+14+2]    ; y_lh
  push  ax
  movw  ax,[sp+12+4]    ; y_ll
  push  ax
  movw  ax,[sp+6+6]   ; x_lh
  movw  de,ax
  movw  ax,[sp+4+6]   ; x_ll
  movw  bc,ax
  movw  ax,[sp+4]   ; return address
  call  !!__COM_mulul   ; ret = x_l * y_l
;
  ; since _COM_mulul does not destroy the argument, y_l is used as it is
  movw  ax,[sp+10+6]    ; x_hh
  movw  bc,ax
  movw  ax,[sp+8+6]   ; x_hl
  call  !!__COM_lmul
  call  !!__REL_llmul_addh  ; ret_h += (x_h * y_l)
  movw  ax,[sp+18+6]    ; y_hh
  movw  [sp+2],ax
  movw  ax,[sp+16+6]    ; y_hl
  movw  [sp+0],ax
  movw  ax,[sp+6+6]   ; x_lh
  movw  bc,ax
  movw  ax,[sp+4+6]   ; x_ll
  call  !!__COM_lmul
  call  !!__REL_llmul_addh  ; ret_h += (x_l * y_h)
  addw  sp,#6
  ret
.Lfunc_end1:
  .size __COM_llmul, .Lfunc_end1-__COM_llmul

  .weak ___muldi3
  .type ___muldi3,@function
  .set  ___muldi3, __COM_llmul
