/** @file
  Simulated MediaTek MT7922 behind MTK_BT_TRANSPORT, for host-based tests.

  It mirrors the USB I/O contract (control transfers never report the received
  length; an empty WMT poll leaves the caller's buffer untouched) and records
  the first protocol violation it sees.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MTK_BT_SIM_H_
#define MTK_BT_SIM_H_

#include <Library/MtkBtLib.h>

#define MTK_SIM_MAX_SECTIONS  4

typedef struct {
  MTK_BT_TRANSPORT    Transport;   ///< Must stay first

  //
  // Configuration.
  //
  UINT32              ChipId;
  UINT32              FwVersion;
  UINT32              SectionCount;
  UINT32              DlAddr[MTK_SIM_MAX_SECTIONS];
  UINT32              DlSize[MTK_SIM_MAX_SECTIONS];
  CONST UINT8         *Expected[MTK_SIM_MAX_SECTIONS];
  BOOLEAN             Loaded[MTK_SIM_MAX_SECTIONS];
  UINT32              BusyReplies;      ///< "busy" answers left for queries
  UINT32              EmptyPolls;       ///< empty polls before each event
  BOOLEAN             NeverReply;       ///< hung chip: no events at all
  UINT32              ResetDonePolls;   ///< MISC reads until reset-done shows
  BOOLEAN             ReportShort;      ///< Flag short IN replies, as EDK2 does
  BOOLEAN             ShortRegisterReads; ///< Answer register reads with 2 bytes

  //
  // State.
  //
  UINT8               Pending[MTK_WMT_EVENT_BUFFER_SIZE];
  UINTN               PendingLength;
  UINT32              EmptyPollsLeft;
  INT32               Active;           ///< section being received, -1 if none
  UINT32              Received;
  BOOLEAN             FunctionOn;
  BOOLEAN             ResetInProgress;
  UINT32              ResetPolls;
  UINT32              RegSubsysRst;
  UINT32              RegEpRstOpt;
  UINT32              RegUdmaIntSta;

  //
  // Statistics.
  //
  UINT32              Commands;
  UINT32              Queries;
  UINT32              Chunks;
  UINT32              Polls;
  UINT32              FuncCtrls;
  UINT64              ElapsedUs;
  CHAR8               Error[200];       ///< first violation, empty if none
} MTK_SIM;

/**
  Set up a simulated chip with no sections; add them with MtkSimAddSection.
**/
VOID
MtkSimInit (
  OUT MTK_SIM  *Sim
  );

VOID
MtkSimAddSection (
  IN OUT MTK_SIM      *Sim,
  IN     UINT32       DlAddr,
  IN     UINT32       DlSize,
  IN     CONST UINT8  *Expected,
  IN     BOOLEAN      Loaded
  );

#endif // MTK_BT_SIM_H_
