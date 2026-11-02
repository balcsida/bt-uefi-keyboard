/** @file
  EDK2 glue around the NimBLE host: hooks into the port, logging, fatal
  error handling, and the scan API.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/NimbleHostLib.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "nimble/nimble_port.h"
#include "Port/nimble_uefi_port.h"

STATIC NIMBLE_HOST_HCI            mHci;
STATIC BOOLEAN                    mInitialized;
STATIC BOOLEAN                    mSynced;
STATIC INT32                      mResetReason;
STATIC BOOLEAN                    mScanning;
STATIC NIMBLE_HOST_SCAN_CALLBACK  mScanCallback;
STATIC VOID                       *mScanContext;
STATIC CHAR8                      mLogLine[256];
STATIC UINTN                      mLogLength;

//
// Hooks for the port (plain C calling convention) wrapping the EFIAPI callbacks.
//

STATIC
uint32_t
HookNowMs (
  void
  )
{
  return mHci.NowMs (mHci.Context);
}

STATIC
void
HookPump (
  void
  )
{
  mHci.Poll (mHci.Context);
}

STATIC
int
HookSendCmd (
  const uint8_t  *Packet,
  size_t         Length
  )
{
  return EFI_ERROR (mHci.SendCommand (mHci.Context, Packet, Length)) ? -1 : 0;
}

STATIC
int
HookSendAcl (
  const uint8_t  *Packet,
  size_t         Length
  )
{
  if (mHci.SendAcl == NULL) {
    return -1;
  }

  return EFI_ERROR (mHci.SendAcl (mHci.Context, Packet, Length)) ? -1 : 0;
}

//
// Logging: NimBLE writes lines in pieces; collect until a newline.
//

STATIC
VOID
FlushLog (
  VOID
  )
{
  if (mLogLength != 0) {
    mLogLine[mLogLength] = '\0';
    if (mHci.Log != NULL) {
      mHci.Log (mHci.Context, mLogLine);
    }

    mLogLength = 0;
  }
}

void
nimble_uefi_vlog (
  int         level,
  const char  *fmt,
  va_list     ap
  )
{
  CHAR8  Piece[256];
  int    Length;
  int    Index;

  if ((mHci.Log == NULL) || ((UINT32)level < mHci.LogLevel)) {
    return;
  }

  Length = vsnprintf (Piece, sizeof (Piece), fmt, ap);
  if (Length > (int)sizeof (Piece) - 1) {
    Length = (int)sizeof (Piece) - 1;
  }

  for (Index = 0; Index < Length; Index++) {
    if (Piece[Index] == '\n') {
      FlushLog ();
    } else if (mLogLength < sizeof (mLogLine) - 1) {
      mLogLine[mLogLength++] = Piece[Index];
    }
  }
}

//
// Fatal errors inside NimBLE. A shell app can exit; nothing better to do.
//

void
abort (
  void
  )
{
  FlushLog ();
  Print (L"NimBLE: fatal error, exiting\n");
  gBS->Exit (gImageHandle, EFI_ABORTED, 0, NULL);
  CpuDeadLoop ();
  for ( ; ; ) {
  }
}

void
nimble_uefi_assert (
  const char  *file,
  int         line,
  const char  *expr
  )
{
  Print (L"NimBLE: assertion \"%a\" failed at %a:%d\n", expr, file, line);
  abort ();
}

//
// Host callbacks
//

STATIC
void
OnSync (
  void
  )
{
  mSynced = TRUE;
}

STATIC
void
OnReset (
  int  Reason
  )
{
  mSynced      = FALSE;
  mResetReason = Reason;
}

EFI_STATUS
EFIAPI
NimbleHostInit (
  IN CONST NIMBLE_HOST_HCI  *Hci
  )
{
  struct nimble_uefi_hooks  Hooks;

  if ((Hci == NULL) || (Hci->SendCommand == NULL) || (Hci->Poll == NULL) || (Hci->NowMs == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (mInitialized) {
    return EFI_ALREADY_STARTED;
  }

  CopyMem (&mHci, Hci, sizeof (mHci));
  Hooks.now_ms   = HookNowMs;
  Hooks.pump     = HookPump;
  Hooks.send_cmd = HookSendCmd;
  Hooks.send_acl = HookSendAcl;
  nimble_uefi_set_hooks (&Hooks);

  nimble_port_init ();
  ble_hs_cfg.sync_cb  = OnSync;
  ble_hs_cfg.reset_cb = OnReset;

  mInitialized = TRUE;
  return EFI_SUCCESS;
}

VOID
EFIAPI
NimbleHostRun (
  VOID
  )
{
  struct ble_npl_eventq  *Queue;
  struct ble_npl_event   *Event;

  if (!mInitialized) {
    return;
  }

  nimble_uefi_pump ();
  nimble_uefi_run_callouts ();
  Queue = nimble_port_get_dflt_eventq ();
  while ((Event = ble_npl_eventq_get (Queue, 0)) != NULL) {
    ble_npl_event_run (Event);
  }

  FlushLog ();
}

BOOLEAN
EFIAPI
NimbleHostSynced (
  VOID
  )
{
  return mSynced;
}

INT32
EFIAPI
NimbleHostResetReason (
  VOID
  )
{
  return mResetReason;
}

EFI_STATUS
EFIAPI
NimbleHostDeliverEvent (
  IN CONST UINT8  *Event,
  IN UINTN        Length
  )
{
  return (nimble_uefi_deliver_evt (Event, Length) == 0) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

EFI_STATUS
EFIAPI
NimbleHostDeliverAcl (
  IN CONST UINT8  *Packet,
  IN UINTN        Length
  )
{
  return (nimble_uefi_deliver_acl (Packet, Length) == 0) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

EFI_STATUS
EFIAPI
NimbleHostGetPublicAddress (
  OUT UINT8  Address[6]
  )
{
  return (ble_hs_id_copy_addr (BLE_ADDR_PUBLIC, Address, NULL) == 0) ? EFI_SUCCESS : EFI_NOT_READY;
}

//
// Scanning
//

STATIC
VOID
FillReport (
  IN  CONST struct ble_gap_disc_desc  *Desc,
  OUT NIMBLE_HOST_ADV_REPORT          *Report
  )
{
  struct ble_hs_adv_fields  Fields;
  UINTN                     Index;
  UINTN                     NameLength;

  ZeroMem (Report, sizeof (*Report));
  CopyMem (Report->Address, Desc->addr.val, 6);
  Report->AddressType = Desc->addr.type;
  Report->EventType   = Desc->event_type;
  Report->Rssi        = Desc->rssi;
  Report->DataLength  = (UINT8)MIN (Desc->length_data, sizeof (Report->Data));
  CopyMem (Report->Data, Desc->data, Report->DataLength);

  if (ble_hs_adv_parse_fields (&Fields, Desc->data, Desc->length_data) != 0) {
    return;
  }

  if ((Fields.name != NULL) && (Fields.name_len > 0)) {
    NameLength = MIN (Fields.name_len, sizeof (Report->Name) - 1);
    CopyMem (Report->Name, Fields.name, NameLength);
    Report->Name[NameLength] = '\0';
  }

  if (Fields.appearance_is_present) {
    Report->HasAppearance = TRUE;
    Report->Appearance    = Fields.appearance;
  }

  for (Index = 0; Index < Fields.num_uuids16; Index++) {
    if (Fields.uuids16[Index].value == 0x1812) {
      Report->HidService = TRUE;
    }
  }
}

STATIC
int
OnGapEvent (
  struct ble_gap_event  *Event,
  void                  *Arg
  )
{
  NIMBLE_HOST_ADV_REPORT  Report;

  switch (Event->type) {
    case BLE_GAP_EVENT_DISC:
      if (mScanCallback != NULL) {
        FillReport (&Event->disc, &Report);
        mScanCallback (mScanContext, &Report);
      }

      break;

    case BLE_GAP_EVENT_DISC_COMPLETE:
      mScanning = FALSE;
      break;

    default:
      break;
  }

  return 0;
}

EFI_STATUS
EFIAPI
NimbleHostStartScan (
  IN BOOLEAN                    Active,
  IN UINT32                     DurationMs,
  IN NIMBLE_HOST_SCAN_CALLBACK  Callback,
  IN VOID                       *Context
  )
{
  struct ble_gap_disc_params  Params;
  int                         Rc;

  if (!mSynced) {
    return EFI_NOT_READY;
  }

  ZeroMem (&Params, sizeof (Params));
  Params.passive           = Active ? 0 : 1;
  Params.filter_duplicates = 0;

  mScanCallback = Callback;
  mScanContext  = Context;
  Rc            = ble_gap_disc (
                    BLE_OWN_ADDR_PUBLIC,
                    (DurationMs == 0) ? BLE_HS_FOREVER : (int32_t)DurationMs,
                    &Params,
                    OnGapEvent,
                    NULL
                    );
  if (Rc != 0) {
    DEBUG ((DEBUG_ERROR, "NimbleHost: ble_gap_disc failed: %d\n", Rc));
    return EFI_DEVICE_ERROR;
  }

  mScanning = TRUE;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
NimbleHostStopScan (
  VOID
  )
{
  int  Rc;

  if (!mScanning) {
    return EFI_NOT_STARTED;
  }

  Rc        = ble_gap_disc_cancel ();
  mScanning = FALSE;
  return (Rc == 0) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

BOOLEAN
EFIAPI
NimbleHostScanning (
  VOID
  )
{
  return mScanning;
}

VOID
EFIAPI
NimbleHostGetStats (
  OUT NIMBLE_HOST_STATS  *Stats
  )
{
  Stats->CommandsSent    = nimble_uefi_stats.cmds_sent;
  Stats->AclSent         = nimble_uefi_stats.acl_sent;
  Stats->EventsDelivered = nimble_uefi_stats.evts_delivered;
  Stats->EventsDropped   = nimble_uefi_stats.evts_dropped;
  Stats->AclDelivered    = nimble_uefi_stats.acl_delivered;
  Stats->AclDropped      = nimble_uefi_stats.acl_dropped;
  Stats->Polls           = nimble_uefi_stats.pumps;
}
