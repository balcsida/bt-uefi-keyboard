/*
 * NimBLE porting layer (NPL) types for single-threaded UEFI.
 *
 * Everything runs on one thread: the caller's loop (or, in the driver, one
 * timer callback) calls NimbleHostRun(), which posts expired callouts and
 * drains the event queue. Blocking primitives (semaphore pend, timed queue
 * get, delay) poll the HCI transport while they wait, so command completions
 * can arrive.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#ifndef _NIMBLE_NPL_OS_H_
#define _NIMBLE_NPL_OS_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_NPL_OS_ALIGNMENT    4
#define BLE_NPL_TIME_FOREVER    UINT32_MAX

/* One tick is one millisecond. */
typedef uint32_t ble_npl_time_t;
typedef int32_t ble_npl_stime_t;

struct ble_npl_eventq;

struct ble_npl_event {
    void (*fn)(struct ble_npl_event *ev);
    void *arg;
    bool queued;
    struct ble_npl_event *next;
};

struct ble_npl_eventq {
    struct ble_npl_event *head;
    struct ble_npl_event *tail;
};

struct ble_npl_callout {
    struct ble_npl_event ev;
    struct ble_npl_eventq *evq;
    ble_npl_time_t expiry;
    bool active;
    struct ble_npl_callout *next;
};

struct ble_npl_mutex {
    uint32_t depth;
};

struct ble_npl_sem {
    uint32_t tokens;
};

#ifdef __cplusplus
}
#endif

#endif /* _NIMBLE_NPL_OS_H_ */
