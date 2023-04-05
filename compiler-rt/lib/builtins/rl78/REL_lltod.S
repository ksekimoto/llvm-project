//===-- REL_lltod.S - Implement _REL_lltod-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements _REL_lltod for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

  .file   "REL_lltod.S"
  .extern __REL_setexp_ll
  .extern __REL_d_round

  .text

  .globl __REL_lltod
  .type  __REL_lltod,@function
__REL_lltod:
  ;-------------------------------------------------------
  ; check if the input value is 0
  ;-------------------------------------------------------
  mov     a,[hl+7]
  or      a,[hl+6]
  or      a,[hl+5]
  or      a,[hl+4]
  mov     c,a             ; for upper 32bit 0 judgment
  or      a,[hl+3]
  or      a,[hl+2]
  or      a,[hl+1]
  or      a,[hl]
  bnz     $0f
  clrw    ax
  movw    [de],ax         ; substitute 0 for the return value
  movw    [de+2],ax
  movw    [de+4],ax
  movw    [de+6],ax
  ret                     ; if the input value is 0, 0 is returned
0:
  ;-------------------------------------------------------
  ; find the value of the exponent part
  ; shift left until the most significant bit of bc-ax is set
  ; decrease the value of the exponent part by the number of left shifts
  ;-------------------------------------------------------
  push    de              ; save the return address
  push    bc              ; save sign
  call    !!__REL_setexp_ll
  mov     a,d
  shrw    ax,8
  addw    ax,#1023        ; add the bias value (1023) of the exponent part
  movw    de,ax

  ;-------------------------------------------------------
  ; round the mantissa and adjust the bit position to match the double format
  ;-------------------------------------------------------
  pop     ax              ; set the sign to a.7
  shl a,7   ;
  call    !!__REL_d_round ; a.7 = code, de = exponential part, [hl] = mantissa part
  pop     de              ; get the return address
  ; stored in the return address
  movw    ax,[hl+6]
  movw    [de+6],ax
  movw    ax,[hl+4]
  movw    [de+4],ax
  movw    ax,[hl+2]
  movw    [de+2],ax
  movw    ax,[hl]
  movw    [de],ax

  ret
.Lfunc_end1:
  .size __REL_lltod, .Lfunc_end1-__REL_lltod
