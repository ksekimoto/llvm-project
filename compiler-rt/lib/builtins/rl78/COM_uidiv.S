//===-- COM_uidiv.S - Implement _COM_uidiv-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_uidiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file  "COM_uidiv.s"

#include "S1_S2/mda.S"

  .text
  .globl  __COM_uidiv
  .type  __COM_uidiv,@function

.LBB_0:
  decw  ax
  ret
__COM_uidiv:
  movw  de,ax    ; x
  clrw  ax
  cmpw  ax,bc    ; if (y == 0) then ret = -1
  bz  $.LBB_0
#ifdef __RL78_S3__
  movw  ax,bc
  xchw  ax,de
  divhu
  ret
#elif defined(__MDA_ENABLED__)
;  if using hl register, modify the _com_sidiv function.
  movw  ax,de
  push  psw
  di
  mov  !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax    ; MDAL <- x
  movw  ax,bc    ; MDBL <- y
  movw  MDBL,ax    ;
  clrw  ax    ; MDAH, MDBH <- 0
  movw  MDAH,ax    ;
  movw  MDBH,ax    ;
;
  mov  !LOWW(MDUC),#0x81  ; divmode = 1, divst = 1
.LBB_1:
  mov  a,!LOWW(MDUC)    ; if (divst == 1) then wait
  bt  a.0,$.LBB_1    ;
;
  movw  ax,MDAL    ; ret <- MDAL
  pop  psw    ; ei
  ret
#else
  movw  ax,de    ; bc <- x, de <- y
  xchw  ax,bc    ;
  movw  de,ax    ;
  clrw  ax    ; rem = 0
  mov  l,#16    ; count <- 16
.LBB_1:        ; do-until
  shlw  bc,1    ; x <<= 1 (ret <<= 1)
  rolwc  ax,1    ; rem = (rem << 1) | cy 
  cmpw  ax,de    ; if (rem >= y) then
  bc  $.LBB_2    ;
  subw  ax,de    ; rem = rem - y
  inc  c    ; ++ret
.LBB_2:
  dec  l    ; --count
  bnz  $.LBB_1    ; until (count = 0)
  movw  ax,bc
  ret
#endif
.Lfunc_end1:
  .size __COM_uidiv, .Lfunc_end1-__COM_uidiv
  
  .weak  ___udivhi3
  .type  ___udivhi3,@function
  .set  ___udivhi3, __COM_uidiv
