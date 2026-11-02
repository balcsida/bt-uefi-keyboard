/*
 * Internal interface between the NimBLE UEFI port (plain C, NimBLE headers
 * only) and the EDK2 glue in NimbleHost.c.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef NIMBLE_UEFI_PORT_H_
#define NIMBLE_UEFI_PORT_H_

#include <stddef.h>
#include <stdint.h>

struct nimble_uefi_hooks {
    /* Monotonic milliseconds. */
    uint32_t (*now_ms)(void);
    /* Read whatever the controller has and deliver it (events, ACL). */
    void (*pump)(void);
    /* Send an HCI command [opcode LE16][len][params] or ACL packet [hdr][data]. */
    int (*send_cmd)(const uint8_t *pkt, size_t len);
    int (*send_acl)(const uint8_t *pkt, size_t len);
};

void nimble_uefi_set_hooks(const struct nimble_uefi_hooks *hooks);

uint32_t nimble_uefi_now_ms(void);
void nimble_uefi_pump(void);
int nimble_uefi_send_cmd(const uint8_t *pkt, size_t len);
int nimble_uefi_send_acl(const uint8_t *pkt, size_t len);

/* Post callouts whose time has come to their event queues. */
void nimble_uefi_run_callouts(void);

/* Hand a complete HCI event / ACL packet from the controller to the host. */
int nimble_uefi_deliver_evt(const uint8_t *buf, size_t len);
int nimble_uefi_deliver_acl(const uint8_t *buf, size_t len);

/* Statistics for diagnostics. */
struct nimble_uefi_stats {
    uint32_t cmds_sent;
    uint32_t acl_sent;
    uint32_t evts_delivered;
    uint32_t evts_dropped;
    uint32_t acl_delivered;
    uint32_t acl_dropped;
    uint32_t pumps;
};

extern struct nimble_uefi_stats nimble_uefi_stats;

#endif /* NIMBLE_UEFI_PORT_H_ */
