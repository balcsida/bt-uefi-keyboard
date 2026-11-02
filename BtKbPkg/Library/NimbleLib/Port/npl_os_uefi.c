/*
 * NimBLE porting layer for single-threaded UEFI.
 *
 * There are no threads or interrupts. Callouts are kept on a list and posted
 * when nimble_uefi_run_callouts() finds them expired. Anything that would
 * block (semaphore pend, timed queue get, delay) polls the HCI transport
 * through the pump hook while it waits, which is how a command's Command
 * Complete event reaches the host while the host waits for it.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <stddef.h>
#include <string.h>

#include "nimble/nimble_npl.h"
#include "nimble_uefi_port.h"

static struct nimble_uefi_hooks g_hooks;
static struct ble_npl_callout *g_callouts;
static int g_task_marker;

struct nimble_uefi_stats nimble_uefi_stats;

void
nimble_uefi_set_hooks(const struct nimble_uefi_hooks *hooks)
{
    g_hooks = *hooks;
}

uint32_t
nimble_uefi_now_ms(void)
{
    return g_hooks.now_ms != NULL ? g_hooks.now_ms() : 0;
}

void
nimble_uefi_pump(void)
{
    nimble_uefi_stats.pumps++;
    if (g_hooks.pump != NULL) {
        g_hooks.pump();
    }
}

int
nimble_uefi_send_cmd(const uint8_t *pkt, size_t len)
{
    nimble_uefi_stats.cmds_sent++;
    return g_hooks.send_cmd != NULL ? g_hooks.send_cmd(pkt, len) : -1;
}

int
nimble_uefi_send_acl(const uint8_t *pkt, size_t len)
{
    nimble_uefi_stats.acl_sent++;
    return g_hooks.send_acl != NULL ? g_hooks.send_acl(pkt, len) : -1;
}

/*
 * OS
 */

bool
ble_npl_os_started(void)
{
    return true;
}

void *
ble_npl_get_current_task_id(void)
{
    return &g_task_marker;
}

/*
 * Events and queues
 */

void
ble_npl_eventq_init(struct ble_npl_eventq *evq)
{
    evq->head = NULL;
    evq->tail = NULL;
}

static struct ble_npl_event *
eventq_pop(struct ble_npl_eventq *evq)
{
    struct ble_npl_event *ev;

    ev = evq->head;
    if (ev != NULL) {
        evq->head = ev->next;
        if (evq->head == NULL) {
            evq->tail = NULL;
        }
        ev->next = NULL;
        ev->queued = false;
    }

    return ev;
}

struct ble_npl_event *
ble_npl_eventq_get(struct ble_npl_eventq *evq, ble_npl_time_t tmo)
{
    struct ble_npl_event *ev;
    uint32_t start;

    start = nimble_uefi_now_ms();
    for (;;) {
        ev = eventq_pop(evq);
        if (ev != NULL || tmo == 0) {
            return ev;
        }

        if (tmo != BLE_NPL_TIME_FOREVER &&
            (uint32_t)(nimble_uefi_now_ms() - start) >= tmo) {
            return NULL;
        }

        nimble_uefi_pump();
        nimble_uefi_run_callouts();
    }
}

void
ble_npl_eventq_put(struct ble_npl_eventq *evq, struct ble_npl_event *ev)
{
    if (ev->queued) {
        return;
    }

    ev->next = NULL;
    ev->queued = true;
    if (evq->tail != NULL) {
        evq->tail->next = ev;
    } else {
        evq->head = ev;
    }
    evq->tail = ev;
}

void
ble_npl_eventq_remove(struct ble_npl_eventq *evq, struct ble_npl_event *ev)
{
    struct ble_npl_event **link;
    struct ble_npl_event *prev;

    if (!ev->queued) {
        return;
    }

    prev = NULL;
    for (link = &evq->head; *link != NULL; link = &(*link)->next) {
        if (*link == ev) {
            *link = ev->next;
            if (evq->tail == ev) {
                evq->tail = prev;
            }
            ev->next = NULL;
            ev->queued = false;
            return;
        }
        prev = *link;
    }
}

void
ble_npl_event_init(struct ble_npl_event *ev, ble_npl_event_fn *fn, void *arg)
{
    memset(ev, 0, sizeof(*ev));
    ev->fn = fn;
    ev->arg = arg;
}

bool
ble_npl_event_is_queued(struct ble_npl_event *ev)
{
    return ev->queued;
}

void *
ble_npl_event_get_arg(struct ble_npl_event *ev)
{
    return ev->arg;
}

void
ble_npl_event_set_arg(struct ble_npl_event *ev, void *arg)
{
    ev->arg = arg;
}

bool
ble_npl_eventq_is_empty(struct ble_npl_eventq *evq)
{
    return evq->head == NULL;
}

void
ble_npl_event_run(struct ble_npl_event *ev)
{
    ev->fn(ev);
}

/*
 * Mutexes: one thread, so they only count.
 */

ble_npl_error_t
ble_npl_mutex_init(struct ble_npl_mutex *mu)
{
    mu->depth = 0;
    return BLE_NPL_OK;
}

ble_npl_error_t
ble_npl_mutex_pend(struct ble_npl_mutex *mu, ble_npl_time_t timeout)
{
    (void)timeout;
    mu->depth++;
    return BLE_NPL_OK;
}

ble_npl_error_t
ble_npl_mutex_release(struct ble_npl_mutex *mu)
{
    if (mu->depth == 0) {
        return BLE_NPL_BAD_MUTEX;
    }
    mu->depth--;
    return BLE_NPL_OK;
}

/*
 * Semaphores: waiting pumps the transport so the releasing event can arrive.
 */

ble_npl_error_t
ble_npl_sem_init(struct ble_npl_sem *sem, uint16_t tokens)
{
    sem->tokens = tokens;
    return BLE_NPL_OK;
}

ble_npl_error_t
ble_npl_sem_pend(struct ble_npl_sem *sem, ble_npl_time_t timeout)
{
    uint32_t start;

    start = nimble_uefi_now_ms();
    while (sem->tokens == 0) {
        if (timeout == 0) {
            return BLE_NPL_TIMEOUT;
        }
        if (timeout != BLE_NPL_TIME_FOREVER &&
            (uint32_t)(nimble_uefi_now_ms() - start) >= timeout) {
            return BLE_NPL_TIMEOUT;
        }
        nimble_uefi_pump();
    }

    sem->tokens--;
    return BLE_NPL_OK;
}

ble_npl_error_t
ble_npl_sem_release(struct ble_npl_sem *sem)
{
    sem->tokens++;
    return BLE_NPL_OK;
}

uint16_t
ble_npl_sem_get_count(struct ble_npl_sem *sem)
{
    return (uint16_t)sem->tokens;
}

/*
 * Callouts
 */

static void
callout_unlink(struct ble_npl_callout *co)
{
    struct ble_npl_callout **link;

    for (link = &g_callouts; *link != NULL; link = &(*link)->next) {
        if (*link == co) {
            *link = co->next;
            break;
        }
    }
    co->next = NULL;
    co->active = false;
}

void
ble_npl_callout_init(struct ble_npl_callout *co, struct ble_npl_eventq *evq,
                     ble_npl_event_fn *ev_cb, void *ev_arg)
{
    memset(co, 0, sizeof(*co));
    co->evq = evq;
    ble_npl_event_init(&co->ev, ev_cb, ev_arg);
}

ble_npl_error_t
ble_npl_callout_reset(struct ble_npl_callout *co, ble_npl_time_t ticks)
{
    callout_unlink(co);
    co->expiry = nimble_uefi_now_ms() + ticks;
    co->active = true;
    co->next = g_callouts;
    g_callouts = co;
    return BLE_NPL_OK;
}

void
ble_npl_callout_stop(struct ble_npl_callout *co)
{
    callout_unlink(co);
    if (co->evq != NULL) {
        ble_npl_eventq_remove(co->evq, &co->ev);
    }
}

bool
ble_npl_callout_is_active(struct ble_npl_callout *co)
{
    return co->active;
}

ble_npl_time_t
ble_npl_callout_get_ticks(struct ble_npl_callout *co)
{
    return co->expiry;
}

ble_npl_time_t
ble_npl_callout_remaining_ticks(struct ble_npl_callout *co, ble_npl_time_t now)
{
    ble_npl_stime_t diff;

    diff = (ble_npl_stime_t)(co->expiry - now);
    return diff > 0 ? (ble_npl_time_t)diff : 0;
}

void
ble_npl_callout_set_arg(struct ble_npl_callout *co, void *arg)
{
    co->ev.arg = arg;
}

void
nimble_uefi_run_callouts(void)
{
    struct ble_npl_callout **link;
    struct ble_npl_callout *co;
    uint32_t now;

    now = nimble_uefi_now_ms();
    link = &g_callouts;
    while (*link != NULL) {
        co = *link;
        if ((ble_npl_stime_t)(now - co->expiry) >= 0) {
            *link = co->next;
            co->next = NULL;
            co->active = false;
            if (co->evq != NULL) {
                ble_npl_eventq_put(co->evq, &co->ev);
            } else {
                ble_npl_event_run(&co->ev);
            }
            /* The callback may have changed the list; start over. */
            link = &g_callouts;
        } else {
            link = &co->next;
        }
    }
}

/*
 * Time: one tick per millisecond.
 */

ble_npl_time_t
ble_npl_time_get(void)
{
    return nimble_uefi_now_ms();
}

ble_npl_error_t
ble_npl_time_ms_to_ticks(uint32_t ms, ble_npl_time_t *out_ticks)
{
    *out_ticks = ms;
    return BLE_NPL_OK;
}

ble_npl_error_t
ble_npl_time_ticks_to_ms(ble_npl_time_t ticks, uint32_t *out_ms)
{
    *out_ms = ticks;
    return BLE_NPL_OK;
}

ble_npl_time_t
ble_npl_time_ms_to_ticks32(uint32_t ms)
{
    return ms;
}

uint32_t
ble_npl_time_ticks_to_ms32(ble_npl_time_t ticks)
{
    return ticks;
}

void
ble_npl_time_delay(ble_npl_time_t ticks)
{
    uint32_t start;

    start = nimble_uefi_now_ms();
    while ((uint32_t)(nimble_uefi_now_ms() - start) < ticks) {
        nimble_uefi_pump();
    }
}

/*
 * Critical sections: nothing can preempt the host.
 */

uint32_t
ble_npl_hw_enter_critical(void)
{
    return 0;
}

void
ble_npl_hw_exit_critical(uint32_t ctx)
{
    (void)ctx;
}

bool
ble_npl_hw_is_in_critical(void)
{
    return false;
}
