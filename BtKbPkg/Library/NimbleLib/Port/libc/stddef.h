/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef NIMBLE_UEFI_STDDEF_H_
#define NIMBLE_UEFI_STDDEF_H_
typedef __SIZE_TYPE__     size_t;
typedef __PTRDIFF_TYPE__  ptrdiff_t;
#ifndef NULL
#define NULL  ((void *)0)
#endif
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
