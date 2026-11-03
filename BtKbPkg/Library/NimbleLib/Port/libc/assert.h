/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef NIMBLE_UEFI_ASSERT_H_
#define NIMBLE_UEFI_ASSERT_H_
void nimble_uefi_assert (const char *file, int line, const char *expr);
#ifdef NDEBUG
#define assert(e)  ((void)0)
#else
#define assert(e)  ((e) ? (void)0 : nimble_uefi_assert (__FILE__, __LINE__, #e))
#endif
#ifndef __cplusplus
#define static_assert  _Static_assert
#endif
#endif
