//===-- COM_ucrem.S - Implement _COM_ucrem-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_ucrem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_ucrem.S"

  .text

  .globl __COM_ucrem
  .type  __COM_ucrem,@function
__COM_ucrem:
#ifdef __RL78_S3__
  cmp0  x   ; if (y == 0) then ret = x
  bz  $0f
  movw  de,ax   ; e <- y
  shrw  ax,8    ; x <- x
  mov d,a
  divhu
  mov a,e   ; ret = rem
0:
  ret
#elif defined(__MDA_ENABLED__)
  cmp0  x   ; if (y == 0) then ret = x
  bz  $0f
  movw  de,ax   ; e <- y
  shrw  ax,8    ; x <- x
  mov d,a
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; MDAL <- x
  movw  ax,de
  movw  MDBL,ax   ; MDBL <- y
  clrw  ax
  movw  MDAH,ax   ; MDAH <- 0
  movw  MDBH,ax   ; MDBH <- 0
;
  mov !LOWW(MDUC),#0x81 ; divmode = 1, divst = 1
1:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$1b    ;
;
  movw  ax,!LOWW(MDCL)  ; ret <- MDCL
  pop psw   ; ei
  mov a,x
0:
  ret
#else
  cmp0  x   ; if (y == 0) then ret = x
  bz  $0f
  movw  de,ax   ; e <- y
  mov d,#8    ; count = 8
  clrb  x   ; x <- x, rem = 0
  xch a,x   ;
1:        ; do-until
  addw  ax,ax   ; x <<= 1 (ret <<= 1), rem = (rem << 1) | cy
  cmp a,e
  bc  $2f    ; if (rem >= y) then
  sub a,e   ; rem = rem - y
  inc x   ; ++ret
2:
  dec d   ; --count
  bnz $1b    ; until(count = 0)
0:
  ret
#endif
.Lfunc_end1:
  .size __COM_ucrem, .Lfunc_end1-__COM_ucrem
