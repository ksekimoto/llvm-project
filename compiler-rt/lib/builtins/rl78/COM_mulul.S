//===-- COM_mulul.S - Implement COM_mulul-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements COM_mulul for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#include "S1_S2/mda.S"

  .file   "COM_mulul.S"
  .extern __COM_mului

  .text

  .globl __COM_mulul
  .type  __COM_mulul,@function
__COM_mulul:
  push  de    ; x
  push  bc    ;
  push  ax    ; return address
  ; x: [sp+2],Ay: [sp+10]

  ; x_l * y_l
  movw  ax,[sp+10]
#ifdef __RL78_S3__
  mulhu
#else
  call !!__COM_mului
#endif
  pop hl
  movw  [hl],ax
  movw  ax,bc
  movw  [hl+2],ax
  push  hl

  ; x_h * y_l
  movw  ax,[sp+4]
  movw  bc,ax
  movw  ax,[sp+10]
#ifdef __RL78_S3__
  mulhu
#else
  call !!__COM_mului
#endif
  pop hl
  addw  ax,[hl+2]
  movw  [hl+2],ax
  sknc      ; because the maximum value of addition is 0xfe01 + 0xfe = 0xfeff
  incw  bc    ; no overflow due to bc increment
  movw  ax,bc
  movw  [hl+4],ax
  push  hl

  ; x_l * y_h
  movw  ax,[sp+2]
  movw  bc,ax
  movw  ax,[sp+12]
#ifdef __RL78_S3__
  mulhu
#else
  call !!__COM_mului
#endif
  pop hl
  addw  ax,[hl+2]
  movw  [hl+2],ax
  sknc      ; because the maximum value of multiplication is 0xfe01
  incw  bc    ; no overflow due to bc increment
  movw  ax,[hl+4]
  addw  ax,bc
  movw  [hl+4],ax
  clrw  ax
  rolwc ax,1
  movw  [hl+6],ax
  push  hl

  ; x_h * y_h
  movw  ax,[sp+4]
  movw  bc,ax
  movw  ax,[sp+12]
#ifdef __RL78_S3__
  mulhu
#else
  call !!__COM_mului
#endif
  pop hl
  addw  ax,[hl+4]
  movw  [hl+4],ax
  sknc      ; because the maximum value of multiplication is 0xfe01
  incw  bc    ; no overflow due to bc increment
  movw  ax,bc
  addw  ax,[hl+6]
  movw  [hl+6],ax

  addw  sp,#4   ; x
  ret
.Lfunc_end1:
  .size __COM_mulul, .Lfunc_end1-__COM_mulul
