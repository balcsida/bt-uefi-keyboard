/*
 * NimBLE HCI transport, controller side ("custom" LL transport): commands and
 * ACL data go to the UEFI glue's send hooks; events and ACL data from the
 * controller come back through nimble_uefi_deliver_evt/acl.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "syscfg/syscfg.h"
#include "os/os_mbuf.h"
#include "nimble/ble.h"
#include "nimble/hci_common.h"
#include "nimble/transport.h"
#include "nimble/transport_impl.h"
#include "nimble_uefi_port.h"

#define NIMBLE_UEFI_MAX_ACL  (BLE_HCI_DATA_HDR_SZ + MYNEWT_VAL(BLE_TRANSPORT_ACL_SIZE))

void
ble_transport_ll_init(void)
{
}

int
ble_transport_to_ll_cmd_impl(void *buf)
{
    uint8_t *cmd;
    int rc;

    cmd = buf;
    rc = nimble_uefi_send_cmd(cmd, 3 + (size_t)cmd[2]);
    ble_transport_free(buf);
    return rc == 0 ? 0 : BLE_ERR_HW_FAIL;
}

int
ble_transport_to_ll_acl_impl(struct os_mbuf *om)
{
    uint8_t pkt[NIMBLE_UEFI_MAX_ACL];
    uint16_t len;
    int rc;

    len = OS_MBUF_PKTLEN(om);
    if (len > sizeof(pkt)) {
        rc = BLE_ERR_MEM_CAPACITY;
    } else if (os_mbuf_copydata(om, 0, len, pkt) != 0) {
        rc = BLE_ERR_UNSPECIFIED;
    } else {
        rc = nimble_uefi_send_acl(pkt, len) == 0 ? 0 : BLE_ERR_HW_FAIL;
    }

    os_mbuf_free_chain(om);
    return rc;
}

int
ble_transport_to_ll_iso_impl(struct os_mbuf *om)
{
    os_mbuf_free_chain(om);
    return BLE_ERR_UNSUPPORTED;
}

static int
evt_is_discardable(const uint8_t *buf, size_t len)
{
    if (len < 3 || buf[0] != BLE_HCI_EVCODE_LE_META) {
        return 0;
    }

    switch (buf[2]) {
    case BLE_HCI_LE_SUBEV_ADV_RPT:
    case BLE_HCI_LE_SUBEV_DIRECT_ADV_RPT:
    case BLE_HCI_LE_SUBEV_EXT_ADV_RPT:
        return 1;
    default:
        return 0;
    }
}

int
nimble_uefi_deliver_evt(const uint8_t *buf, size_t len)
{
    uint8_t *ev;
    int rc;

    if (len < 2 || len != 2 + (size_t)buf[1] ||
        len > MYNEWT_VAL(BLE_TRANSPORT_EVT_SIZE)) {
        nimble_uefi_stats.evts_dropped++;
        return -1;
    }

    ev = ble_transport_alloc_evt(evt_is_discardable(buf, len));
    if (ev == NULL) {
        nimble_uefi_stats.evts_dropped++;
        return -1;
    }

    memcpy(ev, buf, len);
    rc = ble_transport_to_hs_evt(ev);
    if (rc != 0) {
        ble_transport_free(ev);
        nimble_uefi_stats.evts_dropped++;
        return rc;
    }

    nimble_uefi_stats.evts_delivered++;
    return 0;
}

int
nimble_uefi_deliver_acl(const uint8_t *buf, size_t len)
{
    struct os_mbuf *om;
    int rc;

    if (len < BLE_HCI_DATA_HDR_SZ) {
        nimble_uefi_stats.acl_dropped++;
        return -1;
    }

    om = ble_transport_alloc_acl_from_ll();
    if (om == NULL) {
        nimble_uefi_stats.acl_dropped++;
        return -1;
    }

    if (os_mbuf_append(om, buf, (uint16_t)len) != 0) {
        os_mbuf_free_chain(om);
        nimble_uefi_stats.acl_dropped++;
        return -1;
    }

    rc = ble_transport_to_hs_acl(om);
    if (rc != 0) {
        nimble_uefi_stats.acl_dropped++;
        return rc;
    }

    nimble_uefi_stats.acl_delivered++;
    return 0;
}
