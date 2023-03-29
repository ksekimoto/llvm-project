//===-- COM_screm.S - Implement _COM_screm-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_screm for the compiler_rt library.
//
//===----------------------------------------------------------------------===//
#include "S1_S2/mda.S"

  .file   "COM_screm.S"
#ifndef __RL78_S3__
  .extern __COM_ucrem
#endif

  .text

  .globl __COM_screm
  .type  __COM_screm,@function
__COM_screm:
  cmp0  x   ; if (y == 0) then ret = x
  bz  $0f
  clrb  c   ; sign_flag = 0
  bf  a.7,$1f  ; if (x < 0) then
  inc c   ;   sign_flag = 1
  xor a,#0x0ff  ;   x = -x
  inc a   ;
1:
  xch a,x   ; a = y, x = x
  bf  a.7,$2f  ; if (y < 0) then
  xor a,#0x0ff  ;   y = -y
  inc a   ;
2:
#ifdef __RL78_S3__
  mov e,a   ; e = y
  clrb  a   ; a = 0
  mov d,a   ; d = 0
  divhu
  mov a,e   ; ret = rem
#else
  xch a,x   ; a = x, x = y
  call  !!__COM_ucrem ; ret = x % y
#endif
  dec c
  bnz $0f   ; if (sign_flag == 1) then
  xor a,#0x0ff  ;   ret = -ret
  inc a   ;
0:
  ret
.Lfunc_end1:
  .size __COM_screm, .Lfunc_end1-__COM_screm
