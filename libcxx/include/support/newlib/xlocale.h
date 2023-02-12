//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef _LIBCPP_SUPPORT_NEWLIB_XLOCALE_H
#define _LIBCPP_SUPPORT_NEWLIB_XLOCALE_H

#if defined(_NEWLIB_VERSION)

#include <cstdlib>
#include <clocale>
#include <cwctype>
#include <ctype.h>
#if !defined(__NEWLIB__) || __NEWLIB__ < 3 || \
    __NEWLIB__ == 3 && __NEWLIB_MINOR__ < 2 || \
    __NEWLIB__ == 4 && __NEWLIB_MINOR__ < 2 

#if defined(__STRICT_ANSI__) && __POSIX_VISIBLE < 200809
#include <support/xlocale/__nop_locale_mgmt.h>
#endif

#include <support/xlocale/__posix_l_fallback.h>
#include <support/xlocale/__strtonum_fallback.h>

#ifdef __cplusplus
extern "C" {
#endif

int vasprintf (char **, const char *, __VALIST)
               _ATTRIBUTE ((__format__ (__printf__, 2, 0)));

#ifdef __cplusplus
}
#endif


#if defined(__STRICT_ANSI__) && __POSIX_VISIBLE < 200809

#ifdef __cplusplus
extern "C" {
#endif



int isascii (int __c);
int toascii (int __c);
#define _tolower(__c) ((unsigned char)(__c) - 'A' + 'a')
#define _toupper(__c) ((unsigned char)(__c) - 'a' + 'A')

 

size_t mbsnrtowcs(wchar_t *__restrict dst, const char **__restrict src,
                  size_t nmc, size_t len, mbstate_t *__restrict ps);
size_t wcsnrtombs(char *__restrict dst, const wchar_t **__restrict src,
                  size_t nwc, size_t len, mbstate_t *__restrict ps);


locale_t newlocale (int, const char *, locale_t);
void freelocale (locale_t);
locale_t duplocale (locale_t);
locale_t uselocale (locale_t);

#ifdef __cplusplus
}
#endif

#endif

#endif

#endif // _NEWLIB_VERSION

#endif
