//===-- COM_slrem.S - Implement __modsi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __modsi3 for the COMpiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_slrem.S"
#ifndef __RL78_S3__
  .extern __COM_ulrem
#endif

  .text

0:
  pop ax
  movw  ax,de   ; x_l
  ret

  .globl __COM_slrem
  .type  __COM_slrem,@function
__COM_slrem:
  movw  de,ax   ; x_l
  clrw  ax
  push  ax    ; sign_flag = 0
  movw  hl,sp
  movw  ax,[sp+6] ; if (y == 0) then ret = x
  or  a,x
  or  a,[hl+8]
  or  a,[hl+9]
  bz  $0b
  mov a,b
  bf  a.7,$1f  ; if (x < 0) then
  inc [hl+0]    ;   sign_flag = 1
  clrw  ax    ;   x = -x
  subw  ax,de   ;
  movw  de,ax   ;
  subc  a,a   ;
  mov x,a   ;
  subw  ax,bc   ;
  movw  bc,ax   ;
1:
  movw  ax,[hl+8]
  bf  a.7,$2f  ; if (y < 0) then
  clrw  ax    ;   y = -y
  subw  ax,[hl+6] ;
  movw  [hl+6],ax ;
  subc  a,a   ;
  mov x,a   ;
  subw  ax,[hl+8] ;
2:
#ifdef __RL78_S3__
  movw  hl,ax   ; hl = y_h
  movw  ax,[sp+6] ; y_l
  xchw  ax,de   ; ax = x_l, de = y_l
  divwu
  pop bc    ; sign_flag
  dec c
  movw  ax,hl
  bnz $3f   ; if (sign_flag == 1) then ret = -ret
  clrw  ax
  subw  ax,de
  movw  de,ax
  subc  a,a
  mov x,a
  subw  ax,hl
3:
  movw  bc,ax
  movw  ax,de
  ret
#else
  push  ax    ; y_h
  movw  ax,[hl+6] ; y_l
  push  ax    ;
  movw  ax,de   ; x_l
  call  !!__COM_ulrem
  addw  sp,#4   ; y
  pop de    ; sign_flag (hazard)
  dec e
  bnz $3f   ; if (sign_flag == 1) then ret = -ret
  movw  de,ax
  clrw  ax
  subw  ax,de
  movw  de,ax
  subc  a,a
  mov x,a
  subw  ax,bc
  movw  bc,ax
  movw  ax,de
3:
  ret
#endif
.Lfunc_end1:
  .size __COM_slrem, .Lfunc_end1-__COM_slrem

  .weak ___modsi3
  .type ___modsi3,@function
  .set  ___modsi3, __COM_slrem
