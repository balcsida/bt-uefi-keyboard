/** @file
  Apache NimBLE host stack for single-threaded UEFI, behind an EDK2-typed API.

  The caller owns the HCI transport: it supplies send functions, a poll
  function that reads what the controller has and hands it back through
  NimbleHostDeliverEvent/Acl, and a millisecond clock. NimbleHostRun() must
  be called regularly (an app loop, or a periodic timer in a driver); NimBLE
  calls Poll itself while it waits for a command to complete.

  Consumers never include NimBLE headers; only this library does.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef NIMBLE_HOST_LIB_H_
#define NIMBLE_HOST_LIB_H_

#include <Uefi.h>

#define NIMBLE_HOST_LOG_DEBUG  0
#define NIMBLE_HOST_LOG_INFO   1
#define NIMBLE_HOST_LOG_WARN   2
#define NIMBLE_HOST_LOG_ERROR  3
#define NIMBLE_HOST_LOG_OFF    5

typedef struct {
  /// [opcode LE16][parameter length][parameters]
  EFI_STATUS    (EFIAPI *SendCommand)(IN VOID *Context, IN CONST UINT8 *Packet, IN UINTN Length);
  /// [handle/flags LE16][data length LE16][data]
  EFI_STATUS    (EFIAPI *SendAcl)(IN VOID *Context, IN CONST UINT8 *Packet, IN UINTN Length);
  /// Read whatever the controller has ready and pass it to NimbleHostDeliver*.
  VOID          (EFIAPI *Poll)(IN VOID *Context);
  /// Monotonic milliseconds.
  UINT32        (EFIAPI *NowMs)(IN VOID *Context);
  /// Optional: one NimBLE log line, without the newline.
  VOID          (EFIAPI *Log)(IN VOID *Context, IN CONST CHAR8 *Line);
  UINT32        LogLevel;
  VOID          *Context;
} NIMBLE_HOST_HCI;

typedef struct {
  UINT8      Address[6];      ///< As sent on the air: Address[5] is the most significant byte
  UINT8      AddressType;     ///< 0 public, 1 random, 2/3 resolved identity
  UINT8      EventType;       ///< 0 ADV_IND, 1 ADV_DIRECT_IND, 2 ADV_SCAN_IND, 3 ADV_NONCONN_IND, 4 SCAN_RSP
  INT8       Rssi;
  UINT8      DataLength;
  UINT8      Data[31];
  CHAR8      Name[32];        ///< Complete or shortened local name, if present
  BOOLEAN    HasAppearance;
  UINT16     Appearance;
  BOOLEAN    HidService;      ///< 0x1812 listed in the 16-bit service UUIDs
} NIMBLE_HOST_ADV_REPORT;

typedef
VOID
(EFIAPI *NIMBLE_HOST_SCAN_CALLBACK)(
  IN VOID                          *Context,
  IN CONST NIMBLE_HOST_ADV_REPORT  *Report
  );

typedef struct {
  UINT32    CommandsSent;
  UINT32    AclSent;
  UINT32    EventsDelivered;
  UINT32    EventsDropped;
  UINT32    AclDelivered;
  UINT32    AclDropped;
  UINT32    Polls;
} NIMBLE_HOST_STATS;

/**
  Initialize NimBLE and queue the host start (HCI reset and controller
  setup happen on the following NimbleHostRun calls).
**/
EFI_STATUS
EFIAPI
NimbleHostInit (
  IN CONST NIMBLE_HOST_HCI  *Hci
  );

/**
  One round: poll the transport, post expired timers, run queued events.
**/
VOID
EFIAPI
NimbleHostRun (
  VOID
  );

/**
  TRUE once the host and controller are in sync (NimBLE's sync callback ran).
**/
BOOLEAN
EFIAPI
NimbleHostSynced (
  VOID
  );

/**
  Reason passed to NimBLE's reset callback (0 if none), e.g. after a failed
  controller setup.
**/
INT32
EFIAPI
NimbleHostResetReason (
  VOID
  );

EFI_STATUS
EFIAPI
NimbleHostDeliverEvent (
  IN CONST UINT8  *Event,
  IN UINTN        Length
  );

EFI_STATUS
EFIAPI
NimbleHostDeliverAcl (
  IN CONST UINT8  *Packet,
  IN UINTN        Length
  );

EFI_STATUS
EFIAPI
NimbleHostGetPublicAddress (
  OUT UINT8  Address[6]
  );

/**
  Start LE discovery (legacy scanning). DurationMs 0 means until stopped.
**/
EFI_STATUS
EFIAPI
NimbleHostStartScan (
  IN BOOLEAN                    Active,
  IN UINT32                     DurationMs,
  IN NIMBLE_HOST_SCAN_CALLBACK  Callback,
  IN VOID                       *Context
  );

EFI_STATUS
EFIAPI
NimbleHostStopScan (
  VOID
  );

BOOLEAN
EFIAPI
NimbleHostScanning (
  VOID
  );

VOID
EFIAPI
NimbleHostGetStats (
  OUT NIMBLE_HOST_STATS  *Stats
  );

#endif // NIMBLE_HOST_LIB_H_
