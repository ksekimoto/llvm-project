//===-- COM_divui.S - Implement _COM_divui-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_divui for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#include "S1_S2/mda.S"

  .file "COM_divui.S"

  .text

  .globl __COM_divui
  .type  __COM_divui,@function
__COM_divui:
  cmp0  c   ; y
  bnz $1f   ; if (y == 0) then ret = -1
  clrw  ax
  decw  ax
  ret
1:
#ifdef __RL78_S3__
  movw  de,ax
  movw  ax,bc
  clrb  a
  xchw  ax,de
  divhu
;
  ret
#else
#ifdef __MDA_ENABLED__
  push  psw
  di
  mov !LOWW(MDUC),#0x080 ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- x
  movw  ax,bc   ; MDBL <- y
  clrb  a   ;
  movw  MDBL,ax   ;
  clrw  ax
  movw  MDAH,ax   ; MDAH <- 0
  movw  MDBH,ax   ; MDBH <- 0
;
  mov !LOWW(MDUC),#0x81  ; divmode = 1, divst = 1
2:
  mov a,!LOWW(MDUC)    ; if (divst == 1) then wait
  bt  a.0,$2b   ;
;
  movw  ax,MDAL   ; ret <- MDAL
  pop psw
  ret
#else
  clrb  b
  xchw  ax,bc   ; bc <- x
  movw  de,ax   ; de <= y
  clrw  ax    ; rem = 0
  mov l,#16   ; count <- 16
2:        ; do-until
  shlw  bc,1    ; x <<= 1 (ret <<= 1)
  rolwc ax,1    ; rem = (rem << 1) | cy 
  cmpw  ax,de   ; if (rem >= y) then
  bc  $3f   ;
  subw  ax,de   ; rem = rem - y
  inc c   ; ++ret
3:
  dec l   ; --count
  bnz $2b   ; until (count = 0)
  movw  ax,bc
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_divui, .Lfunc_end1-__COM_divui
