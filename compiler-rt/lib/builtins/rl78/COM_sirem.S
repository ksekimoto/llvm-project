//===-- COM_sirem.S - Implement _COM_sirem-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_sirem for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_sirem.S"
#ifndef __RL78_S3__
  .extern __COM_uirem
#endif

  .text

  .globl __COM_sirem
  .type  __COM_sirem,@function

#ifdef __RL78_S3__
__COM_sirem:
  movw  de,ax   ; de = x
  clrw  ax
  cmpw  ax,bc   ; if (y == 0) then ret = x
  bz  $0f
  movw  hl,ax   ; hl = 0
  movw  ax,bc   ; ax = y
  bf  a.7,$1f  ; if (y < 0) then
  clrw  ax    ;   y = -y
  subw  ax,bc   ;
1:
  xchw  ax,de   ; ax = x, de = y
  bf  a.7,$2f  ; if (x < 0) then
  inc l   ;   sign_flag = 1
  movw  bc,ax   ;   x = -x
  clrw  ax    ;
  subw  ax,bc   ;
2:
  divhu
  dec l
  bnz $0f   ; if (sign_flag == 1) then
  clrw  ax    ;   ret = -ret
  subw  ax,de   ;
  ret
0:
  movw  ax,de   ; ret = rem
  ret
#else
#ifndef __OPTIMIZE_SIZE__
__COM_sirem:
  push   de                  ; save de (we don't want to clobber it)

  mov    e, #0               ; E[b1] = negate quot, E[b0] = negate rem
  bf     a.7, $.LBB_0            ; numerator >= 0 ?

  movw   de, ax              ; negate numerator
  clrw   ax
  subw   ax, de

  mov    e, #1               ; consider both quotient and remainder negative for now

.LBB_0:
  push   ax
  mov    a, b                ; denominator >= 0 ?
  and    a, #0x80
  pop    ax
  bz     $.LBB_1

  push   ax                  ; negate denominator
  clrw   ax
  subw   ax, bc
  movw   bc, ax
  pop    ax

  ;xor    r4, #2             ; negate the quotient sign

.LBB_1:

  xchw    ax, bc        ; ax = den, bc = num
  cmpw    ax, #0        ; return 0 if den is 0
  sknz
  br $.LBB_6

  push    de
  push    hl

  movw    hl, ax        ; hl = den
  clrw    ax            ; ax = 0

  mov     e, #16        ; for each bit of the numerator

.LBB_2:  shlw    bc, 1         ; ax:bc <<= 1 (bc's LSB becomes 0)
  rolwc   ax, 1

  cmpw    ax, hl        ; if (ax < den) goto 1
  bc      $.LBB_3

  subw    ax, hl        ; ax -= den
  inc     c             ; and set of the LSB in bc

.LBB_3:  dec     e             ; continue until all the bits in
  bnz     $.LBB_2           ; numerator (bc) are processed / replaced

  pop     hl
  pop     de

  xchw    ax, bc


.LBB_4:  xchw ax,bc
  push   ax
  mov    a, e
  and    a, #0x1
  pop    ax
  bz     $.LBB_5

  movw   de, ax              ; negate quotient in ax
  clrw   ax
  subw   ax, de

.LBB_5:  pop    de                  ; restore de's value before return

  ret


.LBB_6:  pop de
  clrw ax
  clrw bc
  ret

#else
__COM_sirem:
  movw  hl,ax   ; hl = x
  clrw  ax
  cmpw  ax,bc   ; if (y == 0) then ret = x
  xchw  ax,hl   ; ax = x, hl = 0
  bz  $0f
  bf  a.7,$1f  ; if (x < 0) then
  inc l   ;   sign_flag = 1
  movw  de,ax   ;   x = -x
  clrw  ax    ;
  subw  ax,de   ;
1:
  xchw  ax,bc   ; ax = y, bc = x
  bf  a.7,$2f  ; if (y < 0) then
  movw  de,ax   ;   y = -y
  clrw  ax    ;
  subw  ax,de   ;
2:
  xchw  ax,bc   ; ax = x, bc = y
#ifdef __MDA_ENABLED__
  call  !!__COM_uirem ; ret = x % y
#else
  push  hl    ; sign_flag
  call  !!__COM_uirem ; ret = x % y
  pop hl    ; sign_flag
#endif
  dec l
  bnz $0f   ; if (sign_flag == 1) then
  movw  bc,ax   ;   ret = -ret
  clrw  ax    ;
  subw  ax,bc   ;
0:
  ret
#endif
#endif
.Lfunc_end1:
  .size __COM_sirem, .Lfunc_end1-__COM_sirem

  .weak ___modhi3
  .type ___modhi3,@function
  .set  ___modhi3, __COM_sirem
