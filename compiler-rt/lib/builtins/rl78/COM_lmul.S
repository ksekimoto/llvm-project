//===-- COM_lmul.S - Implement __mulsi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __mulsi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_lmul.S"

  .text

  .globl __COM_lmul
  .type  __COM_lmul,@function
__COM_lmul:
#ifdef __RL78_S3__
  push  ax    ; x_l
  movw  ax,[sp+4+2] ; tmp = (x_h * y_l)_l
  mulhu     ;
  movw  de,ax   ;
;
  movw  ax,[sp+0] ; tmp += (x_l * y_h)_l
  movw  bc,ax   ;
  movw  ax,[sp+6+2] ;
  mulhu     ;
  addw  ax,de   ;
  movw  de,ax   ;
;
  pop bc    ; ret = x_l * y_l
  movw  ax,[sp+4] ;
  mulhu     ;
  xchw  ax,bc   ; ret_h += tmp
  addw  ax,de   ;
  xchw  ax,bc   ;
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  clrb  !LOWW(MDUC) ; divmode,macmode,mdsm = 0
;
  movw  MDAL,ax   ; x_l
  movw  ax,[sp+6+2] ; y_h
  movw  MDAH,ax   ;
  nop
  movw  de,!LOWW(MDBL)  ; de = (x_l * y_h)_l
;
  movw  ax,[sp+4+2] ; y_l
  movw  MDAH,ax   ;
  nop
  movw  ax,MDBH   ; de = (x_l * y_h)_l + (x_l * y_l)_h
  addw  ax,de   ;
  movw  de,ax   ;
  movw  ax,MDBL   ; (x_l * y_l)_l
;
  xchw  ax,bc   ; ret_l = (x_h * y_l)_l
  movw  MDAL,ax   ; x_h
  nop
  movw  ax,MDBL   ; (x_h * y_l)_l
  pop psw
  addw  ax,de   ; ret_h = (x_l * y_h)_l + (x_l * y_l)_h
  xchw  ax,bc   ;    + (x_h * y_l)_l
;
  ret
#else
  movw  de,ax   ; x_l
;
  movw  ax,[sp+4] ; x_hh * y_ll
  mov a,b   ;
  mulu  x   ;
  movw  hl,ax   ; ret_hh
;
  movw  ax,bc   ; x_hl * y_lh
  mov a,[sp+5]  ;
  mulu  x   ;
  addw  ax,hl   ; ret_hh
  movw  hl,ax   ;
;
  movw  ax,[sp+6] ; x_lh * y_hl
  mov a,d   ;
  mulu  x   ;
  addw  ax,hl   ; ret_hh
  movw  hl,ax   ;
;
  movw  ax,de   ; x_ll * y_hh
  mov a,[sp+7]  ;
  mulu  x   ;
  addw  ax,hl   ; ret_hh
  shlw  ax,8
  movw  hl,ax   ; ret_h
;
  movw  ax,[sp+4] ; x_hl * y_ll
  mov a,c   ;
  mulu  x   ;
  addw  ax,hl   ; ret_h
  movw  hl,ax   ;
;
  mov a,d   ; x_lh * y_lh
  mov x,a   ;
  mov a,[sp+5]  ;
  mulu  x   ;
  addw  ax,hl   ; ret_h
  movw  hl,ax   ;
;
  movw  ax,[sp+6] ; x_ll * y_hl
  mov a,e   ;
  mulu  x   ;
  addw  ax,hl   ; ret_h
  movw  bc,ax   ; 
;
  movw  ax,[sp+4] ; x_ll * y_lh
  mov a,d   ;
  mulu  x   ;
  movw  hl,ax   ; tmp
;
  movw  ax,de   ; x_lh * y_ll
  mov a,[sp+5]  ;
  mulu  x   ;
  addw  ax,hl   ; (x_ll * y_lh) + (x_lh * y_ll)
  movw  hl,ax   ;
  sknc
  inc b   ; ret_hh
  shrw  ax,8
  addw  ax,bc
  movw  bc,ax
;
  movw  ax,[sp+4] ; x_ll * y_ll
  mov a,e   ;
  mulu  x   ;
  add a,l   ; ret_lh
  sknc
  incw  bc    ; ret_h
;
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_lmul, .Lfunc_end1-__COM_lmul

.weak ___mulsi3
.type ___mulsi3,@function
.set  ___mulsi3, __COM_lmul
