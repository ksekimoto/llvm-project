//===-- COM_lsar.S - Implement COM_lsar-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements COM_lsar for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file "COM_lsar.S"

  .text

  .globl __COM_lsar
  .type  __COM_lsar,@function
#ifndef __OPTIMIZE_SIZE__
1:      ; n >= 8
  sub a,#8    ; n = n - 8
  xch a,e
  mov x,a   ; x = x >> 8
  mov a,c   ;
  xchw  ax,bc   ;
  sarw  ax,8    ;
  xchw  ax,bc   ;
#endif
__COM_lsar:
  xch a,e
#ifndef __OPTIMIZE_SIZE__
  cmp a,#8
  bnc $1b ; if (n >= 8) then 1
#endif
  cmp0  a
  xch a,e
  bz  $3f   ; if (n == 0) then return
2:
  shrw  ax,1    ; x = x >> 1
  xchw  ax,bc   ;
  sarw  ax,1    ;
  xchw  ax,bc   ;
  mov1  a.7,cy    ;
  dec e   ; --n
  bnz $2b   ; until (n == 0)
3:
  ret
.Lfunc_end1:
  .size __COM_lsar, .Lfunc_end1-__COM_lsar

  .weak ___ashrsi3
  .type ___ashrsi3,@function
  .set  ___ashrsi3, __COM_lsar
