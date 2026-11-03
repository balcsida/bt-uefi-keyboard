/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef NIMBLE_UEFI_STDIO_H_
#define NIMBLE_UEFI_STDIO_H_
#include <stdarg.h>
#include <stddef.h>
int  vsnprintf (char *buf, size_t size, const char *fmt, va_list ap);
int  snprintf (char *buf, size_t size, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
int  sprintf (char *buf, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
#endif
