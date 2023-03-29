//===-- COM_sidiv.S - Implement _COM_sidiv-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _COM_sidiv for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file  "COM_sidiv.s"
#ifndef __RL78_S3__
  .extern  __COM_uidiv
#endif

  .text
  .globl  __COM_sidiv
  .type  __COM_sidiv,@function
  
.LBB_0:
  decw  ax
  ret
__COM_sidiv:
#ifdef __RL78_S3__
  movw  de,ax    ; de = x
  clrw  ax
  cmpw  ax,bc    ; if (y == 0) then ret = -1
  bz  $.LBB_0
  movw  hl,ax    ; hl = 0
  movw  ax,bc    ; ax = y
  bf  a.7,$.LBB_1  ; if (y < 0) then
  inc  l    ;   sign_flag = 1
  clrw  ax    ;   y = -y
  subw  ax,bc    ;
.LBB_1:
  xchw  ax,de    ; ax = x, de = y
  bf  a.7,$.LBB_2  ; if (x < 0) then
  inc  l    ;   sign_flag ^= 1
  movw  bc,ax    ;   x = -x
  clrw  ax    ;
  subw  ax,bc    ;
.LBB_2:
  divhu
  dec  l
  bnz  $.LBB_3    ; if (sign_flag == 1) then
  movw  bc,ax    ;   ret = -ret
  clrw  ax    ;
  subw  ax,bc    ;
.LBB_3:
  ret
#else
  movw  de,ax    ; de = x
  clrw  ax
  cmpw  ax,bc    ; if (y == 0) then ret = -1
  bz  $.LBB_0
  movw  hl,ax    ; hl = 0
  movw  ax,bc    ; ax = y
  bf  a.7,$.LBB_1  ; if (y < 0) then
  inc  l    ;   sign_flag = 1
  clrw  ax    ;   y = -y
  subw  ax,bc    ;   bc = y
  movw  bc,ax    ;
.LBB_1:
  movw  ax,de    ; ax = x
  bf  a.7,$.LBB_2  ; if (x < 0) then
  inc  l    ;   sign_flag ^= 1
  clrw  ax    ;   x = -x
  subw  ax,de    ;
.LBB_2:
#if __MDA_ENABLED__
  call  !!__COM_uidiv  ; ret = x / y
#else
  push  hl    ; sign_flag
  call  !!__COM_uidiv  ; ret = x / y
  pop  hl    ; sign_flag
#endif
  dec  l
  bnz  $.LBB_3    ; if (sign_flag == 1) then
  movw  bc,ax    ;   ret = -ret
  clrw  ax    ;
  subw  ax,bc    ;
.LBB_3:
  ret
#endif
.Lfunc_end1:
  .size __COM_sidiv, .Lfunc_end1-__COM_sidiv
  
  .weak  ___divhi3
  .type  ___divhi3,@function
  .set  ___divhi3, __COM_sidiv
