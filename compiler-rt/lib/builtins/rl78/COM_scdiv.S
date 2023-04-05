//===-- COM_scdiv.S - Implement __COM_scdiv -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __COM_scdiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
  #include "S1_S2/mda.S"
  .file  "COM_scdiv.S"

  .text

  .globl  __COM_scdiv
  .type  __COM_scdiv,@function
.LBB_0:
  mov  a,#0x0FF
  ret
__COM_scdiv:
  cmp0  x    ; if (y == 0) then ret = -1
  bz  $.LBB_0
  clrb  c    ; sign_flag = 0
  bf  a.7,$.LBB_1 ; if (x < 0) then
  inc  c    ;   sign_flag = 1
  xor  a,#0x0FF  ;   x = -x
  inc  a    ;
.LBB_1:
  xch  a,x    ; a = y, x = x
  bf  a.7,$.LBB_2  ; if (y < 0) then
  inc  c    ;   sign_flag ^= 1
  xor  a,#0x0FF  ;   y = -y
  inc  a    ;
.LBB_2:
#ifdef __RL78_S3__
  mov  e,a    ; e = y
  clrb  a    ; a = 0
  mov  d,a    ; d = 0
  divhu
  mov  a,x    ; a = ret
#else
  xch  a,x    ; a = x, x = y
  call  !!__COM_ucdiv  ; ret = x / y
#endif
  dec  c
  bnz  $.LBB_3    ; if (sign_flag == 1) then
  xor  a,#0x0FF  ;   ret = -ret
  inc  a    ;
.LBB_3:
  ret

.Lfunc_end1:
  .size __COM_scdiv, .Lfunc_end1-__COM_scdiv
