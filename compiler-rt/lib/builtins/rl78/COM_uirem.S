//===-- COM_uirem.S - Implement _COM_uirem-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_uirem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_uirem.S"

  .text

  .globl __COM_uirem
  .type  __COM_uirem,@function
__COM_uirem:
#ifdef __RL78_S3__
  movw  de,ax   ; x
  clrw  ax
  cmpw  ax,bc   ; if (y == 0) then ret = x
  bz  $0f
  movw  ax,bc
  xchw  ax,de
  divhu
0:
  movw  ax,de   ; ret = rem
  ret
#elif defined(__MDA_ENABLED__)
; if using hl register, modify the _com_sirem function.
  movw  de,ax   ; x
  clrw  ax
  cmpw  ax,bc   ; if (y == 0) then ret = x
  movw  ax,de
  bz  $0f
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- x
  movw  ax,bc   ; MDBL <- y
  movw  MDBL,ax   ;
  clrw  ax    ; MDAH, MDBH <- 0
  movw  MDAH,ax   ;
  movw  MDBH,ax   ;
;
  mov !LOWW(MDUC),#0x81 ; divmode = 1, divst = 1
1:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$1b    ;
;
  movw  ax,!LOWW(MDCL)  ; ret <- MDCL
  pop psw   ; ei
0:
  ret
#else
  movw  de,ax   ; x
  clrw  ax
  cmpw  ax,bc   ; if (y == 0) then ret = x
  movw  ax,de
  bz  $0f
  xchw  ax,bc   ; bc <- x, de <- y
  movw  de,ax   ;
  clrw  ax    ; rem = 0
  mov l,#16   ; count <- 16
1:        ; do-until
  shlw  bc,1    ; x <<= 1 (ret <<= 1)
  rolwc ax,1    ; rem = (rem << 1) | cy 
  cmpw  ax,de   ; if (rem >= y) then
  bc  $2f    ;
  subw  ax,de   ; rem = rem - y
  inc c   ; ++ret
2:
  dec l   ; --count
  bnz $1b    ; until (count = 0)
0:
  ret
#endif
.Lfunc_end1:
  .size __COM_uirem, .Lfunc_end1-__COM_uirem

  .weak ___umodhi3
  .type ___umodhi3,@function
  .set  ___umodhi3, __COM_uirem
