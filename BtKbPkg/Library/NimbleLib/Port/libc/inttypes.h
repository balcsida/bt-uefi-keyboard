/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef NIMBLE_UEFI_INTTYPES_H_
#define NIMBLE_UEFI_INTTYPES_H_
#include <stdint.h>
/* X64 LP64: 64-bit types are long. */
#define PRId8   "d"
#define PRIi8   "i"
#define PRIu8   "u"
#define PRIx8   "x"
#define PRIX8   "X"
#define PRId16  "d"
#define PRIi16  "i"
#define PRIu16  "u"
#define PRIx16  "x"
#define PRIX16  "X"
#define PRId32  "d"
#define PRIi32  "i"
#define PRIu32  "u"
#define PRIx32  "x"
#define PRIX32  "X"
#define PRId64  "ld"
#define PRIi64  "li"
#define PRIu64  "lu"
#define PRIx64  "lx"
#define PRIX64  "lX"
#define PRIdPTR "ld"
#define PRIuPTR "lu"
#define PRIxPTR "lx"
#endif
