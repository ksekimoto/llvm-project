//===-- COM_ucdiv.S - Implement __COM_ucdiv -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_ucdiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "S1_S2/mda.S"
  .file  "COM_ucdiv.S"

  .text
  
  .globl  __COM_ucdiv
  .type  __COM_ucdiv,@function

.LBB_00:
  mov  a,#0x0ff
  ret
__COM_ucdiv:
  cmp0  x  ; if (y == 0) then ret = -1
  bz  $.LBB_00
#ifdef __RL78_S3__
  movw  de,ax  ; e <- y
  shrw  ax,8  ; x <- x
  mov  d,a
  divhu
  mov  a,x
  ret
#elif __MDA_ENABLED__
  movw  de,ax  ; e <- y
  shrw  ax,8  ; x <- x
  mov  d,a
  push  psw
  di
  mov  !LOWW(MDUC),#0x080  ; DIVMODE = 1, DIVST = 0
  movw  MDAL,ax  ; MDAL <- x
  movw  ax,de
  movw  MDBL,ax  ; MDBL <- y
  clrw  ax
  movw  MDAH,ax  ; MDAH <- 0
  movw  MDBH,ax  ; MDBH <- 0
  ;
  mov  !LOWW(MDUC),#0x81  ; DIVMODE = 1, DIVST = 1
.LBB_01:
  mov  a,!LOWW(MDUC)  ; if (DIVST == 1) then wait
  bt  a.0,$.LBB_01  ;
  ;
  movw  ax,MDAL  ; ret <- MDAL
  pop  psw  ; EI
  mov  a,x  ; ret
  ret
#else
  movw  de,ax  ; e <- y
  mov  d,#8  ; count = 8
  clrb  x  ; x <- x, rem = 0
  xch  a,x  ;
.LBB_01:    ; do-until
  addw  ax,ax  ; x <<= 1 (ret <<= 1), rem = (rem << 1) | cy
  cmp  a,e
  bc  $.LBB_02  ; if (rem >= y) then
  sub  a,e  ; rem = rem - y
  inc  x  ;   ret
.LBB_02:
  dec  d  ; --count
  bnz  $.LBB_01  ; until(count = 0)
  ;
  mov  a,x  ; ret
  ret
#endif

  .Lfunc_end1:
  .size __COM_ucdiv, .Lfunc_end1-__COM_ucdiv