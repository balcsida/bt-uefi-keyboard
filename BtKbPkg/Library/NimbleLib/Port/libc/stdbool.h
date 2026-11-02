/* Freestanding C library header for NimBLE in UEFI (BtKbPkg). SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NIMBLE_UEFI_STDBOOL_H_
#define NIMBLE_UEFI_STDBOOL_H_
#if !defined (__cplusplus) && (!defined (__STDC_VERSION__) || (__STDC_VERSION__ < 202311L))
#define bool   _Bool
#define true   1
#define false  0
#endif
#define __bool_true_false_are_defined  1
#endif
