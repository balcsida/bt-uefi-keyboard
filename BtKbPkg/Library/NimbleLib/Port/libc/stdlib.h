/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NIMBLE_UEFI_STDLIB_H_
#define NIMBLE_UEFI_STDLIB_H_
#include <stddef.h>
void  *malloc (size_t size);
void  *calloc (size_t count, size_t size);
void  *realloc (void *ptr, size_t size);
void   free (void *ptr);
void   abort (void) __attribute__ ((noreturn));
int    abs (int value);
#endif
