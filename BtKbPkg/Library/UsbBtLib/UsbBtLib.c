/** @file
  USB Bluetooth (HCI over USB) helpers.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/UsbBtLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define USB_ENDPOINT_XFER_MASK  0x03
#define USB_ENDPOINT_XFER_BULK  0x02
#define USB_ENDPOINT_XFER_INT   0x03
#define USB_ENDPOINT_DIR_IN     0x80

#define HCI_READ_SLICE_MS  100

VOID
UsbBtDump (
  IN CONST CHAR8  *Tag,
  IN CONST UINT8  *Data,
  IN UINTN        Length,
  IN UINTN        MaxBytes
  )
{
  UINTN  Index;
  UINTN  Shown;

  Shown = MIN (Length, MaxBytes);
  Print (L"    %a", Tag);
  for (Index = 0; Index < Shown; Index++) {
    Print (L" %02x", Data[Index]);
  }

  if (Shown < Length) {
    Print (L" ... (%u bytes)", (UINT32)Length);
  }

  Print (L"\n");
}

EFI_STATUS
UsbBtFindInterfaces (
  OUT USB_BT_DEVICE  **Devices,
  OUT UINTN          *Count,
  OUT UINTN          *Scanned
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *Handles;
  UINTN                         HandleCount;
  UINTN                         Index;
  UINTN                         EpIndex;
  EFI_USB_IO_PROTOCOL           *UsbIo;
  EFI_USB_DEVICE_DESCRIPTOR     DeviceDesc;
  EFI_USB_INTERFACE_DESCRIPTOR  InterfaceDesc;
  EFI_USB_ENDPOINT_DESCRIPTOR   EndpointDesc;
  USB_BT_DEVICE                 *List;
  USB_BT_DEVICE                 *Entry;
  UINTN                         Found;

  *Devices = NULL;
  *Count   = 0;
  *Scanned = 0;

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiUsbIoProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR (Status)) {
    return (Status == EFI_NOT_FOUND) ? EFI_SUCCESS : Status;
  }

  *Scanned = HandleCount;

  List = AllocateZeroPool (HandleCount * sizeof (USB_BT_DEVICE));
  if (List == NULL) {
    FreePool (Handles);
    return EFI_OUT_OF_RESOURCES;
  }

  Found = 0;
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (Handles[Index], &gEfiUsbIoProtocolGuid, (VOID **)&UsbIo);
    if (EFI_ERROR (Status)) {
      continue;
    }

    if (EFI_ERROR (UsbIo->UsbGetDeviceDescriptor (UsbIo, &DeviceDesc)) ||
        EFI_ERROR (UsbIo->UsbGetInterfaceDescriptor (UsbIo, &InterfaceDesc)))
    {
      continue;
    }

    if ((InterfaceDesc.InterfaceClass != MTK_BT_USB_CLASS) ||
        (InterfaceDesc.InterfaceSubClass != MTK_BT_USB_SUBCLASS) ||
        (InterfaceDesc.InterfaceProtocol != MTK_BT_USB_PROTOCOL))
    {
      continue;
    }

    Entry = &List[Found];
    ZeroMem (Entry, sizeof (*Entry));
    Entry->Handle          = Handles[Index];
    Entry->UsbIo           = UsbIo;
    Entry->VendorId        = DeviceDesc.IdVendor;
    Entry->ProductId       = DeviceDesc.IdProduct;
    Entry->InterfaceNumber = InterfaceDesc.InterfaceNumber;

    for (EpIndex = 0; EpIndex < InterfaceDesc.NumEndpoints; EpIndex++) {
      if (EFI_ERROR (UsbIo->UsbGetEndpointDescriptor (UsbIo, (UINT8)EpIndex, &EndpointDesc))) {
        continue;
      }

      switch (EndpointDesc.Attributes & USB_ENDPOINT_XFER_MASK) {
        case USB_ENDPOINT_XFER_INT:
          if ((EndpointDesc.EndpointAddress & USB_ENDPOINT_DIR_IN) != 0) {
            Entry->IntInEndpoint  = EndpointDesc.EndpointAddress;
            Entry->IntInMaxPacket = EndpointDesc.MaxPacketSize & 0x7FF;
          }

          break;
        case USB_ENDPOINT_XFER_BULK:
          if ((EndpointDesc.EndpointAddress & USB_ENDPOINT_DIR_IN) != 0) {
            Entry->BulkInEndpoint = EndpointDesc.EndpointAddress;
          } else {
            Entry->BulkOutEndpoint = EndpointDesc.EndpointAddress;
          }

          break;
        default:
          break;
      }
    }

    //
    // Only the HCI interface (events + ACL) is useful. Combo parts also
    // expose a voice interface (isochronous only) and MediaTek a separate
    // ISO-data interface (interrupt only) with the same class codes.
    //
    if ((Entry->IntInEndpoint == 0) || (Entry->BulkInEndpoint == 0) || (Entry->BulkOutEndpoint == 0)) {
      continue;
    }

    Found++;
  }

  FreePool (Handles);

  if (Found == 0) {
    FreePool (List);
    return EFI_SUCCESS;
  }

  *Devices = List;
  *Count   = Found;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
UsbBtControlTransfer (
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
  USB_BT_DEVICE           *Device;
  EFI_USB_DEVICE_REQUEST  DeviceRequest;
  EFI_STATUS              Status;
  UINT32                  UsbStatus;

  Device = (USB_BT_DEVICE *)This;

  DeviceRequest.RequestType = RequestType;
  DeviceRequest.Request     = Request;
  DeviceRequest.Value       = Value;
  DeviceRequest.Index       = Index;
  DeviceRequest.Length      = (UINT16)DataLength;

  UsbStatus = 0;
  Status    = Device->UsbIo->UsbControlTransfer (
                               Device->UsbIo,
                               &DeviceRequest,
                               (DataLength == 0) ? EfiUsbNoData : Direction,
                               TimeoutMs,
                               Data,
                               DataLength,
                               &UsbStatus
                               );
  if (Short != NULL) {
    *Short = FALSE;
  }

  //
  // EDK2's UsbBusDxe reports a successful but short control transfer as
  // EFI_DEVICE_ERROR with no USB error bits. Short IN replies are normal
  // here (the MediaTek event poll), so pass them up as success.
  //
  if ((Status == EFI_DEVICE_ERROR) && (UsbStatus == EFI_USB_NOERROR) && (Direction == EfiUsbDataIn)) {
    if (Short != NULL) {
      *Short = TRUE;
    }

    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    Print (
      L"    control transfer %02x/%02x value %04x index %04x failed: %r (USB status 0x%x)\n",
      RequestType,
      Request,
      Value,
      Index,
      Status,
      UsbStatus
      );
  }

  return Status;
}

STATIC
VOID
EFIAPI
UsbBtStall (
  IN MTK_BT_TRANSPORT  *This,
  IN UINTN             Microseconds
  )
{
  gBS->Stall (Microseconds);
}

VOID
UsbBtInitTransport (
  IN OUT USB_BT_DEVICE  *Device
  )
{
  Device->Transport.ControlTransfer = UsbBtControlTransfer;
  Device->Transport.Stall           = UsbBtStall;
}

/**
  Read one HCI event from the interrupt endpoint, one max-size packet at a
  time, and reassemble it from the header length.
**/
EFI_STATUS
UsbBtReadEvent (
  IN  USB_BT_DEVICE  *Device,
  OUT UINT8          *Buffer,
  IN  UINTN          BufferSize,
  OUT UINTN          *EventLength,
  IN  UINT32         TimeoutMs
  )
{
  EFI_STATUS  Status;
  UINTN       Got;
  UINTN       Need;
  UINTN       Length;
  UINT32      UsbStatus;
  UINTN       Packet;

  Packet = (Device->IntInMaxPacket != 0) ? Device->IntInMaxPacket : 16;
  Got    = 0;
  Need   = 2;

  while (Got < Need) {
    if (Got + Packet > BufferSize) {
      return EFI_BUFFER_TOO_SMALL;
    }

    Length    = Packet;
    UsbStatus = 0;
    Status    = Device->UsbIo->UsbSyncInterruptTransfer (
                                 Device->UsbIo,
                                 Device->IntInEndpoint,
                                 Buffer + Got,
                                 &Length,
                                 (Got == 0) ? TimeoutMs : 1000,
                                 &UsbStatus
                                 );
    if (EFI_ERROR (Status)) {
      if ((Got != 0) && (Status == EFI_TIMEOUT)) {
        Print (L"    partial HCI event (%u of %u bytes)\n", (UINT32)Got, (UINT32)Need);
        return EFI_PROTOCOL_ERROR;
      }

      return Status;
    }

    Got += Length;
    if (Got >= 2) {
      Need = 2 + (UINTN)Buffer[1];
    }
  }

  *EventLength = Need;
  return EFI_SUCCESS;
}

EFI_STATUS
UsbBtSendCommand (
  IN USB_BT_DEVICE  *Device,
  IN CONST UINT8    *Packet,
  IN UINTN          Length
  )
{
  if (Device->Verbose) {
    UsbBtDump ("hci>", Packet, Length, 32);
  }

  return UsbBtControlTransfer (
           &Device->Transport,
           EfiUsbDataOut,
           0x20,
           0x00,
           0,
           0,
           (VOID *)Packet,
           Length,
           2000,
           NULL
           );
}

EFI_STATUS
UsbBtSendAcl (
  IN USB_BT_DEVICE  *Device,
  IN CONST UINT8    *Packet,
  IN UINTN          Length
  )
{
  EFI_STATUS  Status;
  UINTN       Sent;
  UINT32      UsbStatus;

  if (Device->BulkOutEndpoint == 0) {
    return EFI_UNSUPPORTED;
  }

  if (Device->Verbose) {
    UsbBtDump ("acl>", Packet, Length, 32);
  }

  Sent      = Length;
  UsbStatus = 0;
  Status    = Device->UsbIo->UsbBulkTransfer (
                               Device->UsbIo,
                               Device->BulkOutEndpoint,
                               (VOID *)Packet,
                               &Sent,
                               1000,
                               &UsbStatus
                               );
  if (!EFI_ERROR (Status) && (Sent != Length)) {
    Status = EFI_DEVICE_ERROR;
  }

  return Status;
}

EFI_STATUS
UsbBtHciCommand (
  IN     USB_BT_DEVICE  *Device,
  IN     UINT16         Opcode,
  IN     CONST VOID     *Params OPTIONAL,
  IN     UINT8          ParamLength,
  OUT    UINT8          *Return OPTIONAL,
  IN OUT UINTN          *ReturnLength OPTIONAL,
  IN     UINT32         TimeoutMs
  )
{
  EFI_STATUS  Status;
  UINT8       Packet[3 + 255];
  UINT8       Event[HCI_MAX_EVENT_SIZE + 64];
  UINTN       EventLength;
  UINT32      WaitedMs;
  UINT16      EventOpcode;
  UINTN       Copy;

  Packet[0] = (UINT8)(Opcode & 0xFF);
  Packet[1] = (UINT8)(Opcode >> 8);
  Packet[2] = ParamLength;
  if (ParamLength != 0) {
    CopyMem (&Packet[3], Params, ParamLength);
  }

  Status = UsbBtSendCommand (Device, Packet, 3 + ParamLength);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (WaitedMs = 0; WaitedMs < TimeoutMs; ) {
    Status = UsbBtReadEvent (Device, Event, sizeof (Event), &EventLength, HCI_READ_SLICE_MS);
    if (Status == EFI_TIMEOUT) {
      WaitedMs += HCI_READ_SLICE_MS;
      continue;
    }

    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (Device->Verbose) {
      UsbBtDump ("hci<", Event, EventLength, 32);
    }

    if ((Event[0] == HCI_EVENT_COMMAND_COMPLETE) && (Event[1] >= 3)) {
      EventOpcode = (UINT16)(Event[3] | (Event[4] << 8));
      if (EventOpcode == Opcode) {
        if ((Return != NULL) && (ReturnLength != NULL)) {
          Copy = MIN (*ReturnLength, (UINTN)Event[1] - 3);
          CopyMem (Return, &Event[5], Copy);
          *ReturnLength = Copy;
        }

        return EFI_SUCCESS;
      }
    } else if ((Event[0] == HCI_EVENT_COMMAND_STATUS) && (Event[1] >= 4)) {
      EventOpcode = (UINT16)(Event[4] | (Event[5] << 8));
      if ((EventOpcode == Opcode) && (Event[2] != 0)) {
        Print (L"    command 0x%04x rejected with HCI status 0x%02x\n", Opcode, Event[2]);
        return EFI_DEVICE_ERROR;
      }
    }

    if (!Device->Verbose) {
      UsbBtDump ("skipped event:", Event, EventLength, 16);
    }
  }

  Print (L"    no Command Complete for 0x%04x within %u ms\n", Opcode, TimeoutMs);
  return EFI_TIMEOUT;
}
