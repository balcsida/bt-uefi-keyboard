/*
 * NimBLE log hooks: every module/level pair becomes a call into
 * nimble_uefi_vlog(), which filters by level and hands complete lines to the
 * log callback registered with NimbleHostInit().
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef _NIMBLE_NPL_OS_LOG_H_
#define _NIMBLE_NPL_OS_LOG_H_

#include <stdarg.h>

#define NIMBLE_UEFI_LVL_DEBUG     0
#define NIMBLE_UEFI_LVL_INFO      1
#define NIMBLE_UEFI_LVL_WARN      2
#define NIMBLE_UEFI_LVL_ERROR     3
#define NIMBLE_UEFI_LVL_CRITICAL  4

void nimble_uefi_vlog(int level, const char *fmt, va_list ap);

#define BLE_NPL_LOG_IMPL(lvl)                                                   \
    static inline void                                                          \
    _BLE_NPL_LOG_CAT(BLE_NPL_LOG_MODULE, _BLE_NPL_LOG_CAT(_, lvl))(const char *fmt, ...) \
    {                                                                           \
        va_list ap;                                                             \
        va_start(ap, fmt);                                                      \
        nimble_uefi_vlog(NIMBLE_UEFI_LVL_ ## lvl, fmt, ap);                     \
        va_end(ap);                                                             \
    }

#endif /* _NIMBLE_NPL_OS_LOG_H_ */
