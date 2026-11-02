/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NIMBLE_UEFI_STRING_H_
#define NIMBLE_UEFI_STRING_H_
#include <stddef.h>
void   *memcpy (void *dst, const void *src, size_t n);
void   *memmove (void *dst, const void *src, size_t n);
void   *memset (void *dst, int c, size_t n);
int     memcmp (const void *a, const void *b, size_t n);
void   *memchr (const void *s, int c, size_t n);
size_t  strlen (const char *s);
size_t  strnlen (const char *s, size_t max);
int     strcmp (const char *a, const char *b);
int     strncmp (const char *a, const char *b, size_t n);
char   *strcpy (char *dst, const char *src);
char   *strncpy (char *dst, const char *src, size_t n);
char   *strcat (char *dst, const char *src);
char   *strncat (char *dst, const char *src, size_t n);
char   *strchr (const char *s, int c);
#endif
