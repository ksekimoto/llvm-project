//===-- udivsi3.c - Implement __udivsi3 -----------------------------------===//
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

#include "int_lib.h"

typedef su_int fixuint_t;
typedef si_int fixint_t;
#include "int_div_impl.inc"

// Returns: a / b

#ifdef __MDA_ENABLED__
#include "rl78/MDA.h"
COMPILER_RT_ABI __attribute__((naked)) su_int __udivsi3(su_int n, su_int d) {
  __asm("push	psw");
  __asm("di");
  __asm("mov	!LOWW(" XSTR(MDUC) "), #0x80");
  __asm("movw	" XSTR(MDAL) ", ax");
  __asm("movw	ax, bc");
  __asm("movw " XSTR(MDAH) ", ax");
  __asm("movw	ax, [sp+8]");
  __asm("movw	" XSTR(MDBH) ", ax");
  __asm("movw	ax, [sp+6]");
  __asm("movw	" XSTR(MDBL) ", ax");
  __asm("mov	!LOWW(" XSTR(MDUC) "), #0x81");	//This starts the division op
  __asm("1:");
  __asm("mov	a, !LOWW(" XSTR(MDUC) ")");	//Wait 16 clocks or until DIVST is clear
  __asm("bt	a.0, $1b");
  __asm("movw    ax, " XSTR(MDAH));
  __asm("movw	bc, ax");
  __asm("movw    ax, " XSTR(MDAL));
  __asm("pop	psw");
  __asm("ret");
}

#else
COMPILER_RT_ABI su_int __udivsi3(su_int a, su_int b) {
  return __udivXi3(a, b);
}
#endif

#if defined(__ARM_EABI__)
COMPILER_RT_ALIAS(__udivsi3, __aeabi_uidiv)
#endif
