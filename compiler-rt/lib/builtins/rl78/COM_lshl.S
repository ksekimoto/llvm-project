//===-- COM_lshl.S - Implement COM_lshl-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements COM_lshl for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file "COM_lshl.S"

  .text

  .globl __COM_lshl
  .type  __COM_lshl,@function
#ifndef __OPTIMIZE_SIZE__
1:      ; n >= 8
  sub a,#8    ; n = n - 8
  xch a,e
  shlw  bc,8    ; x = x << 8
  mov c,a   ;
  shlw  ax,8    ;
#endif
__COM_lshl:
  xch a,e
#ifndef __OPTIMIZE_SIZE__
  cmp a,#8
  bnc $1b ; if (n >= 8) then 1
#endif
  cmp0  a
  xch a,e
  bz  $3f   ; if (n == 0) then return
2:
  addw  ax,ax   ; x = x << 1
  rolwc bc,1    ;
  dec e   ; --n
  bnz $2b   ; until (n == 0)
3:
  ret
.Lfunc_end1:
  .size __COM_lshl, .Lfunc_end1-__COM_lshl

  .weak ___ashlsi3
  .type ___ashlsi3,@function
  .set  ___ashlsi3, __COM_lshl
