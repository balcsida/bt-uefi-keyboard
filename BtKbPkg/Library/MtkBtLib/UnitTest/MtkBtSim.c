/** @file
  Simulated MediaTek MT7922 for host-based tests.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MtkBtSim.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

STATIC
VOID
SimFail (
  IN OUT MTK_SIM      *Sim,
  IN     CONST CHAR8  *Message,
  IN     UINT32       Value
  )
{
  if (Sim->Error[0] == '\0') {
    AsciiSPrint (Sim->Error, sizeof (Sim->Error), "%a (0x%x)", Message, Value);
  }
}

STATIC
UINT32
Le32 (
  IN CONST UINT8  *Ptr
  )
{
  return (UINT32)Ptr[0] | ((UINT32)Ptr[1] << 8) | ((UINT32)Ptr[2] << 16) | ((UINT32)Ptr[3] << 24);
}

STATIC
VOID
QueueEvent (
  IN OUT MTK_SIM  *Sim,
  IN     UINT8    Op,
  IN     UINT8    Flag,
  IN     BOOLEAN  WithStatus,
  IN     UINT16   Status
  )
{
  UINT8  Extra;

  Extra            = WithStatus ? 2 : 0;
  Sim->Pending[0]  = MTK_WMT_EVENT_CODE;
  Sim->Pending[1]  = (UINT8)(MTK_WMT_HEADER_SIZE + Extra);
  Sim->Pending[2]  = 0x02;
  Sim->Pending[3]  = Op;
  Sim->Pending[4]  = (UINT8)(1 + Extra);
  Sim->Pending[5]  = 0;
  Sim->Pending[6]  = Flag;
  if (WithStatus) {
    Sim->Pending[7] = (UINT8)(Status >> 8);
    Sim->Pending[8] = (UINT8)(Status & 0xFF);
  }

  Sim->PendingLength  = 2 + MTK_WMT_HEADER_SIZE + Extra;
  Sim->EmptyPollsLeft = Sim->EmptyPolls;
}

STATIC
VOID
HandlePatch (
  IN OUT MTK_SIM      *Sim,
  IN     UINT8        Flag,
  IN     CONST UINT8  *Payload,
  IN     UINTN        Length
  )
{
  UINT32  Index;
  UINT32  Addr;
  UINT32  Size;
  UINT8   ExpectedFlag;

  if (Flag == MTK_WMT_PATCH_QUERY) {
    if ((Length != 1 + MTK_FW_BIN_INFO_SIZE) || (Payload[0] != 0)) {
      SimFail (Sim, "malformed section query, length", (UINT32)Length);
      return;
    }

    if (Sim->Active != -1) {
      SimFail (Sim, "query while a section download is open", (UINT32)Sim->Active);
      return;
    }

    Addr = Le32 (Payload + 1);
    Size = Le32 (Payload + 5);
    for (Index = 0; Index < Sim->SectionCount; Index++) {
      if ((Sim->DlAddr[Index] == Addr) && (Sim->DlSize[Index] == Size)) {
        break;
      }
    }

    if (Index == Sim->SectionCount) {
      SimFail (Sim, "query for unknown section, load address", Addr);
      return;
    }

    Sim->Queries++;
    if (Sim->Loaded[Index]) {
      QueueEvent (Sim, MTK_WMT_OP_PATCH_DOWNLOAD, 2, FALSE, 0);
    } else if (Sim->BusyReplies > 0) {
      Sim->BusyReplies--;
      QueueEvent (Sim, MTK_WMT_OP_PATCH_DOWNLOAD, 1, FALSE, 0);
    } else {
      Sim->Active   = (INT32)Index;
      Sim->Received = 0;
      QueueEvent (Sim, MTK_WMT_OP_PATCH_DOWNLOAD, 0, FALSE, 0);
    }

    return;
  }

  if (Sim->Active == -1) {
    SimFail (Sim, "data chunk without a preceding query, flag", Flag);
    return;
  }

  Index = (UINT32)Sim->Active;
  if ((Length == 0) || (Length > MTK_WMT_MAX_PAYLOAD) || (Sim->Received + Length > Sim->DlSize[Index])) {
    SimFail (Sim, "bad chunk length", (UINT32)Length);
    return;
  }

  if (Sim->Received == 0) {
    ExpectedFlag = MTK_WMT_PATCH_FIRST;
  } else if (Sim->Received + Length == Sim->DlSize[Index]) {
    ExpectedFlag = MTK_WMT_PATCH_LAST;
  } else {
    ExpectedFlag = MTK_WMT_PATCH_CONTINUE;
  }

  if (Flag != ExpectedFlag) {
    SimFail (Sim, "wrong chunk flag at offset", Sim->Received);
    return;
  }

  if ((Sim->Expected[Index] != NULL) && (CompareMem (Payload, Sim->Expected[Index] + Sim->Received, Length) != 0)) {
    SimFail (Sim, "chunk data differs from the image at offset", Sim->Received);
    return;
  }

  Sim->Received += (UINT32)Length;
  Sim->Chunks++;
  if (Sim->Received == Sim->DlSize[Index]) {
    Sim->Loaded[Index] = TRUE;
    Sim->Active        = -1;
  }

  QueueEvent (Sim, MTK_WMT_OP_PATCH_DOWNLOAD, 0, FALSE, 0);
}

STATIC
VOID
HandleHciCommand (
  IN OUT MTK_SIM      *Sim,
  IN     CONST UINT8  *Data,
  IN     UINTN        Length
  )
{
  UINT16  Opcode;
  UINTN   ParamLength;
  UINTN   PayloadLength;
  UINT16  WmtLength;

  if (Length < 3) {
    SimFail (Sim, "HCI command too short", (UINT32)Length);
    return;
  }

  Opcode      = (UINT16)(Data[0] | (Data[1] << 8));
  ParamLength = Data[2];
  if (3 + ParamLength != Length) {
    SimFail (Sim, "HCI parameter length mismatch", (UINT32)ParamLength);
    return;
  }

  if (Opcode != MTK_WMT_HCI_OPCODE) {
    SimFail (Sim, "standard HCI command is not simulated, opcode", Opcode);
    return;
  }

  if (Sim->PendingLength != 0) {
    SimFail (Sim, "new WMT command before the previous event was read, op", Data[4]);
    return;
  }

  if ((ParamLength < MTK_WMT_HEADER_SIZE) || (Data[3] != MTK_WMT_DIR_HOST_TO_CHIP)) {
    SimFail (Sim, "bad WMT header", (UINT32)ParamLength);
    return;
  }

  PayloadLength = ParamLength - MTK_WMT_HEADER_SIZE;
  WmtLength     = (UINT16)(Data[5] | (Data[6] << 8));
  if (WmtLength != PayloadLength + 1) {
    SimFail (Sim, "WMT length field is not payload + 1", WmtLength);
    return;
  }

  Sim->Commands++;
  switch (Data[4]) {
    case MTK_WMT_OP_PATCH_DOWNLOAD:
      HandlePatch (Sim, Data[7], Data + 8, PayloadLength);
      break;

    case MTK_WMT_OP_FUNC_CTRL:
      if (PayloadLength != 1) {
        SimFail (Sim, "FUNC_CTRL payload length", (UINT32)PayloadLength);
        return;
      }

      Sim->FunctionOn = (BOOLEAN)(Data[8] != 0);
      Sim->FuncCtrls++;
      if (Sim->FunctionOn) {
        QueueEvent (Sim, MTK_WMT_OP_FUNC_CTRL, 0, TRUE, 0x0404);
      } else {
        QueueEvent (Sim, MTK_WMT_OP_FUNC_CTRL, 0, FALSE, 0);
      }

      break;

    default:
      SimFail (Sim, "unsimulated WMT op", Data[4]);
      break;
  }
}

STATIC
UINT32
ReadUhw (
  IN OUT MTK_SIM  *Sim,
  IN     UINT32   Reg
  )
{
  switch (Reg) {
    case MTK_BT_UHW_SUBSYS_RST:
      return Sim->RegSubsysRst;
    case MTK_BT_UHW_UDMA_INT_STA:
      return Sim->RegUdmaIntSta;
    case MTK_BT_UHW_MISC:
      if (Sim->ResetInProgress) {
        if (++Sim->ResetPolls >= Sim->ResetDonePolls) {
          Sim->ResetInProgress = FALSE;
        }

        return Sim->ResetInProgress ? 0 : MTK_BT_UHW_RST_DONE;
      }

      return MTK_BT_UHW_RST_DONE;
    default:
      SimFail (Sim, "read of unsimulated UHW register", Reg);
      return 0;
  }
}

STATIC
VOID
WriteUhw (
  IN OUT MTK_SIM  *Sim,
  IN     UINT32   Reg,
  IN     UINT32   Value
  )
{
  UINT32  Index;

  switch (Reg) {
    case MTK_BT_UHW_EP_RST_OPT:
      Sim->RegEpRstOpt = Value;
      break;
    case MTK_BT_UHW_UDMA_INT_STA:
      Sim->RegUdmaIntSta = Value;
      break;
    case MTK_BT_UHW_SUBSYS_RST:
      if (((Value & BIT0) != 0) && ((Sim->RegSubsysRst & BIT0) == 0)) {
        //
        // Reset: firmware and function state are gone.
        //
        for (Index = 0; Index < Sim->SectionCount; Index++) {
          Sim->Loaded[Index] = FALSE;
        }

        Sim->FunctionOn      = FALSE;
        Sim->Active          = -1;
        Sim->ResetInProgress = TRUE;
        Sim->ResetPolls      = 0;
      }

      Sim->RegSubsysRst = Value & ~(UINT32)BIT0;
      break;
    default:
      SimFail (Sim, "write of unsimulated UHW register", Reg);
      break;
  }
}

STATIC
EFI_STATUS
EFIAPI
SimControlTransfer (
  IN     MTK_BT_TRANSPORT        *This,
  IN     EFI_USB_DATA_DIRECTION  Direction,
  IN     UINT8                   RequestType,
  IN     UINT8                   Request,
  IN     UINT16                  Value,
  IN     UINT16                  Index,
  IN OUT VOID                    *Data OPTIONAL,
  IN     UINTN                   DataLength,
  IN     UINT32                  TimeoutMs,
  OUT    BOOLEAN                 *Short OPTIONAL
  )
{
  MTK_SIM  *Sim;
  UINT32   Reg;
  UINT32   RegValue;
  UINT8    *Bytes;

  Sim   = (MTK_SIM *)This;
  Bytes = (UINT8 *)Data;
  Reg   = ((UINT32)Value << 16) | Index;
  if (Short != NULL) {
    *Short = FALSE;
  }

  if ((Direction == EfiUsbDataOut) && (RequestType == 0x20) && (Request == 0x00)) {
    HandleHciCommand (Sim, Bytes, DataLength);
    return EFI_SUCCESS;
  }

  if ((Direction == EfiUsbDataIn) && (RequestType == 0xC0) && (Request == 0x01) && (Value == 0x0030)) {
    Sim->Polls++;
    if (DataLength != MTK_WMT_EVENT_BUFFER_SIZE) {
      SimFail (Sim, "WMT event poll with unexpected length", (UINT32)DataLength);
      return EFI_SUCCESS;
    }

    //
    // Every reply is short: nothing at all when no event is pending, 7-9
    // bytes otherwise. Like UsbIo, no length is returned; EDK2 at least
    // flags the transfer as short.
    //
    if (Short != NULL) {
      *Short = Sim->ReportShort;
    }

    if (Sim->NeverReply || (Sim->PendingLength == 0)) {
      return EFI_SUCCESS;
    }

    if (Sim->EmptyPollsLeft > 0) {
      Sim->EmptyPollsLeft--;
      return EFI_SUCCESS;
    }

    CopyMem (Bytes, Sim->Pending, Sim->PendingLength);
    Sim->PendingLength = 0;
    return EFI_SUCCESS;
  }

  if ((Direction == EfiUsbDataIn) && (RequestType == 0xC0) && (Request == 0x63) && (DataLength == 4)) {
    switch (Reg) {
      case MTK_BT_REG_CHIP_ID_LEGACY:
        RegValue = 0;
        break;
      case MTK_BT_REG_CHIP_ID:
        RegValue = Sim->ChipId;
        break;
      case MTK_BT_REG_FW_VERSION:
        RegValue = Sim->FwVersion;
        break;
      case MTK_BT_REG_FW_FLAVOR:
        RegValue = 0;
        break;
      default:
        SimFail (Sim, "read of unsimulated chip register", Reg);
        return EFI_DEVICE_ERROR;
    }

    if (Sim->ShortRegisterReads) {
      Bytes[0] = (UINT8)RegValue;
      Bytes[1] = (UINT8)(RegValue >> 8);
      if (Short != NULL) {
        *Short = Sim->ReportShort;
      }

      return EFI_SUCCESS;
    }

    WriteUnaligned32 ((UINT32 *)Bytes, RegValue);
    return EFI_SUCCESS;
  }

  if ((Direction == EfiUsbDataIn) && (RequestType == 0xDE) && (Request == 0x01) && (DataLength == 4)) {
    WriteUnaligned32 ((UINT32 *)Bytes, ReadUhw (Sim, Reg));
    return EFI_SUCCESS;
  }

  if ((Direction == EfiUsbDataOut) && (RequestType == 0x5E) && (Request == 0x02) && (DataLength == 4)) {
    WriteUhw (Sim, Reg, ReadUnaligned32 ((UINT32 *)Bytes));
    return EFI_SUCCESS;
  }

  SimFail (Sim, "unexpected control transfer, request type/request", ((UINT32)RequestType << 8) | Request);
  return EFI_DEVICE_ERROR;
}

STATIC
VOID
EFIAPI
SimStall (
  IN MTK_BT_TRANSPORT  *This,
  IN UINTN             Microseconds
  )
{
  ((MTK_SIM *)This)->ElapsedUs += Microseconds;
}

VOID
MtkSimInit (
  OUT MTK_SIM  *Sim
  )
{
  ZeroMem (Sim, sizeof (*Sim));
  Sim->Transport.ControlTransfer = SimControlTransfer;
  Sim->Transport.Stall           = SimStall;
  Sim->ChipId                    = 0x7922;
  Sim->Active                    = -1;
  Sim->ResetDonePolls            = 1;
  Sim->ReportShort               = TRUE;
}

VOID
MtkSimAddSection (
  IN OUT MTK_SIM      *Sim,
  IN     UINT32       DlAddr,
  IN     UINT32       DlSize,
  IN     CONST UINT8  *Expected,
  IN     BOOLEAN      Loaded
  )
{
  if (Sim->SectionCount < MTK_SIM_MAX_SECTIONS) {
    Sim->DlAddr[Sim->SectionCount]   = DlAddr;
    Sim->DlSize[Sim->SectionCount]   = DlSize;
    Sim->Expected[Sim->SectionCount] = Expected;
    Sim->Loaded[Sim->SectionCount]   = Loaded;
    Sim->SectionCount++;
  }
}
