/** @file
  MediaTek MT79xx WMT channel, register access, firmware upload and function
  control over USB endpoint 0.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: MIT OR Apache-2.0
**/

#include <Library/MtkBtLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

//
// Endpoint 0 requests.
//
#define MTK_REQTYPE_HCI_COMMAND  0x20   // class, host to device
#define MTK_REQ_HCI_COMMAND      0x00
#define MTK_REQTYPE_VENDOR_IN    0xC0   // vendor, device to host
#define MTK_REQ_WMT_EVENT        0x01
#define MTK_WMT_EVENT_VALUE      0x0030
#define MTK_REQ_CHIP_REG_READ    0x63
#define MTK_REQTYPE_UHW_READ     0xDE
#define MTK_REQ_UHW_READ         0x01
#define MTK_REQTYPE_UHW_WRITE    0x5E
#define MTK_REQ_UHW_WRITE        0x02

#define MTK_CONTROL_TIMEOUT_MS   2000

#define MTK_QUERY_RETRIES        20
#define MTK_BUSY_DELAY_US        (100 * 1000)
#define MTK_ACTIVATION_DELAY_US  (100 * 1000)

#define MTK_RESET_SETTLE_US      (100 * 1000)
#define MTK_RESET_POLL_US        (20 * 1000)
#define MTK_RESET_TIMEOUT_US     (1000 * 1000)

STATIC
VOID
Trace (
  IN MTK_BT_DEVICE  *Device,
  IN CONST CHAR8    *Tag,
  IN CONST UINT8    *Data,
  IN UINTN          Length
  )
{
  if (Device->Trace != NULL) {
    Device->Trace (Device->CallbackContext, Tag, Data, Length);
  }
}

STATIC
VOID
TraceRegister (
  IN MTK_BT_DEVICE  *Device,
  IN CONST CHAR8    *Tag,
  IN UINT32         Reg,
  IN UINT32         Value
  )
{
  UINT8  Pair[8];

  WriteUnaligned32 ((UINT32 *)&Pair[0], Reg);
  WriteUnaligned32 ((UINT32 *)&Pair[4], Value);
  Trace (Device, Tag, Pair, sizeof (Pair));
}

VOID
EFIAPI
MtkBtInitDevice (
  OUT MTK_BT_DEVICE     *Device,
  IN  MTK_BT_TRANSPORT  *Transport
  )
{
  ZeroMem (Device, sizeof (*Device));
  Device->Transport      = Transport;
  Device->EventTimeoutMs = 5000;
  Device->PollIntervalUs = 500;
}

STATIC
EFI_STATUS
ReadRegister (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT8          RequestType,
  IN  UINT8          Request,
  IN  UINT32         Reg,
  OUT UINT32         *Value
  )
{
  EFI_STATUS  Status;
  UINT8       Buffer[4];
  BOOLEAN     Short;

  if (Value == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Buffer, sizeof (Buffer));
  Short  = FALSE;
  Status = Device->Transport->ControlTransfer (
                                Device->Transport,
                                EfiUsbDataIn,
                                RequestType,
                                Request,
                                (UINT16)(Reg >> 16),
                                (UINT16)(Reg & 0xFFFF),
                                Buffer,
                                sizeof (Buffer),
                                MTK_CONTROL_TIMEOUT_MS,
                                &Short
                                );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MtkBt: read of register 0x%08x failed: %r\n", Reg, Status));
    return Status;
  }

  if (Short) {
    DEBUG ((DEBUG_ERROR, "MtkBt: short read of register 0x%08x\n", Reg));
    return EFI_PROTOCOL_ERROR;
  }

  *Value = ReadUnaligned32 ((UINT32 *)Buffer);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MtkBtReadChipReg (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT32         Reg,
  OUT UINT32         *Value
  )
{
  EFI_STATUS  Status;

  Status = ReadRegister (Device, MTK_REQTYPE_VENDOR_IN, MTK_REQ_CHIP_REG_READ, Reg, Value);
  if (!EFI_ERROR (Status)) {
    TraceRegister (Device, "reg<", Reg, *Value);
  }

  return Status;
}

EFI_STATUS
EFIAPI
MtkBtReadUhwReg (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT32         Reg,
  OUT UINT32         *Value
  )
{
  EFI_STATUS  Status;

  Status = ReadRegister (Device, MTK_REQTYPE_UHW_READ, MTK_REQ_UHW_READ, Reg, Value);
  if (!EFI_ERROR (Status)) {
    TraceRegister (Device, "uhw<", Reg, *Value);
  }

  return Status;
}

EFI_STATUS
EFIAPI
MtkBtWriteUhwReg (
  IN MTK_BT_DEVICE  *Device,
  IN UINT32         Reg,
  IN UINT32         Value
  )
{
  EFI_STATUS  Status;
  UINT8       Buffer[4];

  WriteUnaligned32 ((UINT32 *)Buffer, Value);
  TraceRegister (Device, "uhw>", Reg, Value);
  Status = Device->Transport->ControlTransfer (
                                Device->Transport,
                                EfiUsbDataOut,
                                MTK_REQTYPE_UHW_WRITE,
                                MTK_REQ_UHW_WRITE,
                                (UINT16)(Reg >> 16),
                                (UINT16)(Reg & 0xFFFF),
                                Buffer,
                                sizeof (Buffer),
                                MTK_CONTROL_TIMEOUT_MS,
                                NULL
                                );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MtkBt: write of UHW register 0x%08x failed: %r\n", Reg, Status));
  }

  return Status;
}

EFI_STATUS
EFIAPI
MtkBtGetChipInfo (
  IN  MTK_BT_DEVICE  *Device,
  OUT UINT32         *ChipId,
  OUT UINT32         *FwVersion,
  OUT UINT32         *FwFlavor
  )
{
  EFI_STATUS  Status;
  UINT32      Legacy;

  if ((ChipId == NULL) || (FwVersion == NULL) || (FwFlavor == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *ChipId    = 0;
  *FwVersion = 0;
  *FwFlavor  = 0;

  //
  // MT7663 answers on the legacy register; every newer part on the new one.
  //
  Status = MtkBtReadChipReg (Device, MTK_BT_REG_CHIP_ID_LEGACY, &Legacy);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Legacy == 0x7663) {
    *ChipId = Legacy;
    return EFI_SUCCESS;
  }

  Status = MtkBtReadChipReg (Device, MTK_BT_REG_CHIP_ID, ChipId);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtReadChipReg (Device, MTK_BT_REG_FW_VERSION, FwVersion);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtReadChipReg (Device, MTK_BT_REG_FW_FLAVOR, FwFlavor);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *FwFlavor = (*FwFlavor & BIT7) >> 7;
  return EFI_SUCCESS;
}

/**
  Poll endpoint 0 until the WMT event for Op arrives.

  EFI_USB_IO_PROTOCOL does not return the received length, and the chip
  answers "nothing yet" with a zero-length data stage. Every poll is short
  (an event is 7-9 of the 64 bytes asked for), which EDK2 flags and other
  stacks may not. So the buffer is zeroed before every poll and a reply is
  recognized by a non-zero event code. This assumes the USB stack copies back
  only received bytes; that holds for EDK2's XhciDxe without bounce buffering,
  and must be checked on other stacks.
**/
STATIC
EFI_STATUS
WaitWmtEvent (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT8          Op,
  OUT MTK_WMT_EVENT  *Event
  )
{
  EFI_STATUS  Status;
  UINT8       Buffer[MTK_WMT_EVENT_BUFFER_SIZE];
  UINT64      WaitedUs;
  UINT64      LimitUs;
  UINTN       Length;
  BOOLEAN     Short;

  WaitedUs = 0;
  LimitUs  = MultU64x32 (Device->EventTimeoutMs, 1000);

  for ( ; ; ) {
    ZeroMem (Buffer, sizeof (Buffer));
    Short  = FALSE;
    Status = Device->Transport->ControlTransfer (
                                  Device->Transport,
                                  EfiUsbDataIn,
                                  MTK_REQTYPE_VENDOR_IN,
                                  MTK_REQ_WMT_EVENT,
                                  MTK_WMT_EVENT_VALUE,
                                  0,
                                  Buffer,
                                  sizeof (Buffer),
                                  MTK_CONTROL_TIMEOUT_MS,
                                  &Short
                                  );
    Device->EventPolls++;
    if (Short) {
      Device->ShortPolls++;
    }

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "MtkBt: WMT event poll failed: %r\n", Status));
      return Status;
    }

    if (Buffer[0] != 0) {
      Length = 2 + (UINTN)Buffer[1];
      if (Length > sizeof (Buffer)) {
        Trace (Device, "wmt<", Buffer, sizeof (Buffer));
        DEBUG ((DEBUG_ERROR, "MtkBt: oversized event (length %u)\n", (UINT32)Length));
        return EFI_PROTOCOL_ERROR;
      }

      Trace (Device, "wmt<", Buffer, Length);

      if (Buffer[0] == MTK_WMT_EVENT_CODE) {
        if (Buffer[1] < MTK_WMT_HEADER_SIZE) {
          DEBUG ((DEBUG_ERROR, "MtkBt: WMT event too short (%u)\n", Buffer[1]));
          return EFI_PROTOCOL_ERROR;
        }

        if (Buffer[3] != Op) {
          DEBUG ((DEBUG_ERROR, "MtkBt: WMT event for op 0x%02x, expected 0x%02x\n", Buffer[3], Op));
          return EFI_PROTOCOL_ERROR;
        }

        ZeroMem (Event, sizeof (*Event));
        Event->Op     = Buffer[3];
        Event->Flag   = Buffer[6];
        Event->Length = (UINT8)Length;
        if (Buffer[1] >= MTK_WMT_HEADER_SIZE + 2) {
          Event->HasStatus = TRUE;
          Event->Status    = (UINT16)((Buffer[7] << 8) | Buffer[8]);
        }

        CopyMem (Event->Raw, Buffer, Length);
        return EFI_SUCCESS;
      }

      //
      // Some other HCI event came through endpoint 0. Note it and keep waiting.
      //
      DEBUG ((DEBUG_WARN, "MtkBt: ignoring event 0x%02x while waiting for WMT op 0x%02x\n", Buffer[0], Op));
    }

    if (WaitedUs >= LimitUs) {
      DEBUG ((DEBUG_ERROR, "MtkBt: no WMT event for op 0x%02x after %u ms\n", Op, Device->EventTimeoutMs));
      return EFI_TIMEOUT;
    }

    Device->Transport->Stall (Device->Transport, Device->PollIntervalUs);
    WaitedUs += Device->PollIntervalUs;
  }
}

EFI_STATUS
EFIAPI
MtkBtWmtCommand (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT8          Op,
  IN  UINT8          Flag,
  IN  CONST VOID     *Payload OPTIONAL,
  IN  UINT16         PayloadLength,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  )
{
  EFI_STATUS     Status;
  UINT8          Packet[3 + MTK_WMT_HEADER_SIZE + MTK_WMT_MAX_PAYLOAD];
  UINTN          PacketLength;
  MTK_WMT_EVENT  LocalEvent;

  if ((Device == NULL) || (Device->Transport == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((PayloadLength > MTK_WMT_MAX_PAYLOAD) || ((PayloadLength != 0) && (Payload == NULL))) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // HCI command header, then the WMT header. The WMT length counts the flag
  // byte as well as the payload.
  //
  Packet[0] = (UINT8)(MTK_WMT_HCI_OPCODE & 0xFF);
  Packet[1] = (UINT8)(MTK_WMT_HCI_OPCODE >> 8);
  Packet[2] = (UINT8)(MTK_WMT_HEADER_SIZE + PayloadLength);
  Packet[3] = MTK_WMT_DIR_HOST_TO_CHIP;
  Packet[4] = Op;
  Packet[5] = (UINT8)((PayloadLength + 1) & 0xFF);
  Packet[6] = (UINT8)((PayloadLength + 1) >> 8);
  Packet[7] = Flag;
  if (PayloadLength != 0) {
    CopyMem (&Packet[8], Payload, PayloadLength);
  }

  PacketLength = 3 + MTK_WMT_HEADER_SIZE + PayloadLength;

  Trace (Device, "wmt>", Packet, PacketLength);
  Status = Device->Transport->ControlTransfer (
                                Device->Transport,
                                EfiUsbDataOut,
                                MTK_REQTYPE_HCI_COMMAND,
                                MTK_REQ_HCI_COMMAND,
                                0,
                                0,
                                Packet,
                                PacketLength,
                                MTK_CONTROL_TIMEOUT_MS,
                                NULL
                                );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MtkBt: sending WMT op 0x%02x failed: %r\n", Op, Status));
    return Status;
  }

  Device->WmtCommands++;
  return WaitWmtEvent (Device, Op, (Event != NULL) ? Event : &LocalEvent);
}

EFI_STATUS
EFIAPI
MtkBtQuerySection (
  IN  MTK_BT_DEVICE         *Device,
  IN  CONST MTK_FW_SECTION  *Section,
  OUT MTK_SECTION_STATE     *State
  )
{
  EFI_STATUS     Status;
  UINT8          Payload[1 + MTK_FW_BIN_INFO_SIZE];
  MTK_WMT_EVENT  Event;

  if ((Section == NULL) || (Section->BinInfo == NULL) || (State == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Byte 0 selects the legacy download mode; the rest is the section's bin
  // info block, verbatim.
  //
  Payload[0] = 0;
  CopyMem (&Payload[1], Section->BinInfo, MTK_FW_BIN_INFO_SIZE);

  Status = MtkBtWmtCommand (
             Device,
             MTK_WMT_OP_PATCH_DOWNLOAD,
             MTK_WMT_PATCH_QUERY,
             Payload,
             sizeof (Payload),
             &Event
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  switch (Event.Flag) {
    case 2:
      *State = MtkSectionLoaded;
      break;
    case 1:
      *State = MtkSectionBusy;
      break;
    default:
      *State = MtkSectionNeedsDownload;
      break;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MtkBtDownloadSection (
  IN     MTK_BT_DEVICE         *Device,
  IN     CONST MTK_FW_SECTION  *Section,
  IN     UINT32                SectionIndex,
  IN OUT MTK_FW_LOAD_RESULT    *Result
  )
{
  EFI_STATUS     Status;
  UINT32         Sent;
  UINT32         Length;
  UINT8          Flag;
  MTK_WMT_EVENT  Event;

  if ((Section == NULL) || (Section->Data == NULL) || (Result == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Sent = 0; Sent < Section->DlSize; Sent += Length) {
    Length = MIN (MTK_WMT_MAX_PAYLOAD, Section->DlSize - Sent);

    //
    // The first chunk is always "first", even when it is also the last one.
    //
    if (Sent == 0) {
      Flag = MTK_WMT_PATCH_FIRST;
    } else if (Sent + Length == Section->DlSize) {
      Flag = MTK_WMT_PATCH_LAST;
    } else {
      Flag = MTK_WMT_PATCH_CONTINUE;
    }

    Status = MtkBtWmtCommand (
               Device,
               MTK_WMT_OP_PATCH_DOWNLOAD,
               Flag,
               Section->Data + Sent,
               (UINT16)Length,
               &Event
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "MtkBt: section %u chunk at offset %u failed: %r\n", SectionIndex, Sent, Status));
      return Status;
    }

    //
    // "Busy" in reply to a data chunk means the chip lost track of the
    // download; Linux gives up in that case too.
    //
    if (Event.Flag == 1) {
      DEBUG ((DEBUG_ERROR, "MtkBt: chip reported busy during section %u upload\n", SectionIndex));
      return EFI_PROTOCOL_ERROR;
    }

    Result->ChunksSent++;
    if (Device->Progress != NULL) {
      Device->Progress (Device->CallbackContext, SectionIndex, Sent + Length, Section->DlSize);
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MtkBtLoadFirmware (
  IN  MTK_BT_DEVICE         *Device,
  IN  CONST MTK_FW_IMAGE    *Fw,
  IN  BOOLEAN               AllowDownload,
  OUT MTK_FW_LOAD_RESULT    *Result
  )
{
  EFI_STATUS             Status;
  UINT32                 Index;
  UINT32                 Retries;
  MTK_SECTION_STATE      State;
  CONST MTK_FW_SECTION   *Section;

  if ((Device == NULL) || (Fw == NULL) || (Result == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Result, sizeof (*Result));
  Result->FirstMissingSection = -1;

  for (Index = 0; Index < Fw->SectionCount; Index++) {
    Section = &Fw->Sections[Index];
    if (Section->DlSize == 0) {
      continue;
    }

    Result->SectionsChecked++;

    for (Retries = MTK_QUERY_RETRIES; ; ) {
      Status = MtkBtQuerySection (Device, Section, &State);
      if (EFI_ERROR (Status)) {
        return Status;
      }

      if (State == MtkSectionLoaded) {
        Result->SectionsAlreadyLoaded++;
        break;
      }

      if (State == MtkSectionNeedsDownload) {
        if (!AllowDownload) {
          Result->FirstMissingSection = (INT32)Index;
          return EFI_NOT_STARTED;
        }

        Status = MtkBtDownloadSection (Device, Section, Index, Result);
        if (EFI_ERROR (Status)) {
          return Status;
        }

        Result->SectionsDownloaded++;
        break;
      }

      Result->BusyRetries++;
      if (--Retries == 0) {
        DEBUG ((DEBUG_ERROR, "MtkBt: section %u still busy after %u queries\n", Index, MTK_QUERY_RETRIES));
        return EFI_TIMEOUT;
      }

      Device->Transport->Stall (Device->Transport, MTK_BUSY_DELAY_US);
    }
  }

  //
  // Linux waits for "firmware activation" whether or not anything was sent.
  //
  Device->Transport->Stall (Device->Transport, MTK_ACTIVATION_DELAY_US);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FuncCtrl (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT8          On,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  )
{
  return MtkBtWmtCommand (Device, MTK_WMT_OP_FUNC_CTRL, 0, &On, sizeof (On), Event);
}

EFI_STATUS
EFIAPI
MtkBtEnable (
  IN  MTK_BT_DEVICE  *Device,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  )
{
  EFI_STATUS  Status;

  Status = MtkBtWriteUhwReg (Device, MTK_BT_UHW_EP_RST_OPT, MTK_BT_UHW_EP_RST_IN_OUT);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return FuncCtrl (Device, 1, Event);
}

EFI_STATUS
EFIAPI
MtkBtDisable (
  IN  MTK_BT_DEVICE  *Device,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  )
{
  return FuncCtrl (Device, 0, Event);
}

EFI_STATUS
EFIAPI
MtkBtSubsysReset7922 (
  IN MTK_BT_DEVICE  *Device
  )
{
  EFI_STATUS  Status;
  UINT32      Value;
  UINT32      WaitedUs;
  UINT32      ChipId;

  Status = MtkBtReadUhwReg (Device, MTK_BT_UHW_SUBSYS_RST, &Value);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtWriteUhwReg (Device, MTK_BT_UHW_SUBSYS_RST, Value | 0x00002020);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtWriteUhwReg (Device, MTK_BT_UHW_EP_RST_OPT, MTK_BT_UHW_EP_RST_IN_OUT);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtReadUhwReg (Device, MTK_BT_UHW_SUBSYS_RST, &Value);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtWriteUhwReg (Device, MTK_BT_UHW_SUBSYS_RST, Value | BIT0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Device->Transport->Stall (Device->Transport, MTK_RESET_SETTLE_US);

  for (WaitedUs = 0; ; WaitedUs += MTK_RESET_POLL_US) {
    Status = MtkBtReadUhwReg (Device, MTK_BT_UHW_MISC, &Value);
    if (!EFI_ERROR (Status) && ((Value & MTK_BT_UHW_RST_DONE) != 0)) {
      break;
    }

    if (WaitedUs >= MTK_RESET_TIMEOUT_US) {
      DEBUG ((DEBUG_ERROR, "MtkBt: subsystem reset did not complete\n"));
      return EFI_TIMEOUT;
    }

    Device->Transport->Stall (Device->Transport, MTK_RESET_POLL_US);
  }

  Status = MtkBtWriteUhwReg (Device, MTK_BT_UHW_UDMA_INT_STA, 0x000000FF);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MtkBtReadChipReg (Device, MTK_BT_REG_CHIP_ID, &ChipId);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (ChipId == 0) {
    DEBUG ((DEBUG_ERROR, "MtkBt: chip ID reads 0 after subsystem reset\n"));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}
