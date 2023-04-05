//===-- COM_uldiv.S - Implement __udivsi3-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __udivsi3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_uldiv.S"

  .text

0:
  pop ax
  clrw  ax    ; ret = -1
  decw  ax
  movw  bc,ax
  ret

  .globl __COM_uldiv
  .type  __COM_uldiv,@function
__COM_uldiv:
  push  ax    ; x_l
  movw  hl,sp
  movw  ax,[sp+6] ; if (y == 0) then ret = -1
  or  a,x
  or  a,[hl+8]
  or  a,[hl+9]
  bz  $0b
#ifdef __RL78_S3__
  movw  ax,[hl+6] ; hlde <- y
  movw  de,ax   ;
  movw  ax,[hl+8] ;
  movw  hl,ax   ;
  pop ax    ; x_l
  divwu
  ret
#elif defined(__MDA_ENABLED__)
  pop ax    ; x_l
  push  psw
  di
  mov !LOWW(MDUC),#0x080  ; divmode = 1, divst = 0
  movw  MDAL,ax   ; mda <- x
  movw  ax,bc   ;
  movw  MDAH,ax   ;
  movw  ax,[hl+6] ; mdb <- y
  movw  MDBL,ax   ;
  movw  ax,[hl+8] ;
  movw  MDBH,ax   ;
;
  mov !LOWW(MDUC),#0x081  ; divmode  = 1, divst = 1
1:
  mov a,!LOWW(MDUC)   ; if (divst == 1) then wait
  bt  a.0,$1b
;
  movw  bc,!LOWW(MDAH)  ; ret <- mda
  movw  ax,MDAL   ;
  pop psw
  ret
#else
; [hl+0] x_h [hl+2] count [hl+4] x_l [hl+6] ret [hl+10] y
;
  mov x,#32   ; count = 32
  push  ax    ;
  push  bc    ; x_h
  movw  hl,sp
;
  clrw  ax    ; rem = 0
  movw  bc,ax   ; rem_h
  movw  de,ax   ; rem_l
1:        ; do_until
  movw  ax,[hl+4] ; x <<= 1 (ret <<= 1)
  addw  ax,ax   ;
  movw  [hl+4],ax ;
  movw  ax,[hl]   ;
  rolwc ax,1    ;
  movw  [hl],ax   ;
  movw  ax,de   ; rem = (rem << 1) | cy
  rolwc ax,1    ;
  rolwc bc,1    ;
  xchw  ax,bc   ; if (rem >= y) then
  cmpw  ax,[hl+12]  ;
  xchw  ax,bc   ;
  bc  $3f    ;
  bnz $2f    ;
  cmpw  ax,[hl+10]  ;
  bc  $3f    ;
2:
  xchw  ax,bc   ; rem = rem - y
  subw  ax,[hl+12]  ;
  xchw  ax,bc   ;
  subw  ax,[hl+10]  ;
  sknc      ;
  decw  bc    ;
  incw  [hl+4]    ; ++ret
3:
  movw  de,ax   ; rem_l
  dec [hl+2]    ; --count
  bnz $1b    ; until (count = 0)
;
  pop bc    ; ret_h
  pop ax    ; count
  pop ax    ; ret_l
  ret
#endif
.Lfunc_end1:
  .size __COM_uldiv, .Lfunc_end1-__COM_uldiv

  .weak ___udivsi3
  .type ___udivsi3,@function
  .set  ___udivsi3, __COM_uldiv
