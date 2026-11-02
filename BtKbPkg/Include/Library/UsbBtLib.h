/** @file
  USB Bluetooth (HCI over USB) helpers: interface discovery, the
  MTK_BT_TRANSPORT over EFI_USB_IO_PROTOCOL, HCI commands, event reads and
  ACL writes.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef USB_BT_LIB_H_
#define USB_BT_LIB_H_

#include <Uefi.h>
#include <Protocol/UsbIo.h>
#include <Library/MtkBtLib.h>

#define HCI_EVENT_COMMAND_COMPLETE  0x0E
#define HCI_EVENT_COMMAND_STATUS    0x0F

#define HCI_OP_RESET                 0x0C03
#define HCI_OP_READ_LOCAL_NAME       0x0C14
#define HCI_OP_READ_LOCAL_VERSION    0x1001
#define HCI_OP_READ_BD_ADDR          0x1009
#define HCI_OP_LE_READ_BUFFER_SIZE   0x2002

#define HCI_MAX_EVENT_SIZE           (2 + 255)

typedef struct {
  MTK_BT_TRANSPORT       Transport;    ///< Must stay first
  EFI_HANDLE             Handle;
  EFI_USB_IO_PROTOCOL    *UsbIo;
  UINT16                 VendorId;
  UINT16                 ProductId;
  UINT8                  InterfaceNumber;
  UINT8                  IntInEndpoint;
  UINT16                 IntInMaxPacket;
  UINT8                  BulkInEndpoint;
  UINT8                  BulkOutEndpoint;
  BOOLEAN                Verbose;
} USB_BT_DEVICE;

/**
  Find USB interfaces with class E0/01/01 that carry the HCI endpoints
  (interrupt IN plus bulk IN/OUT); other interfaces with the same class codes
  carry voice or ISO data. Uses cached descriptors only; nothing is sent to
  the device.
**/
EFI_STATUS
UsbBtFindInterfaces (
  OUT USB_BT_DEVICE  **Devices,
  OUT UINTN          *Count,
  OUT UINTN          *Scanned
  );

VOID
UsbBtInitTransport (
  IN OUT USB_BT_DEVICE  *Device
  );

/**
  Send an HCI command and wait for its Command Complete event.

  @param[out]     Return        Return parameters (first byte is the HCI status).
  @param[in,out]  ReturnLength  In: buffer size. Out: bytes copied.
**/
EFI_STATUS
UsbBtHciCommand (
  IN     USB_BT_DEVICE  *Device,
  IN     UINT16         Opcode,
  IN     CONST VOID     *Params OPTIONAL,
  IN     UINT8          ParamLength,
  OUT    UINT8          *Return OPTIONAL,
  IN OUT UINTN          *ReturnLength OPTIONAL,
  IN     UINT32         TimeoutMs
  );

/**
  Send a raw HCI command packet ([opcode LE16][length][parameters]) without
  waiting for its completion.
**/
EFI_STATUS
UsbBtSendCommand (
  IN USB_BT_DEVICE  *Device,
  IN CONST UINT8    *Packet,
  IN UINTN          Length
  );

/**
  Send an ACL data packet ([handle/flags LE16][length LE16][data]) on the
  bulk OUT endpoint.
**/
EFI_STATUS
UsbBtSendAcl (
  IN USB_BT_DEVICE  *Device,
  IN CONST UINT8    *Packet,
  IN UINTN          Length
  );

/**
  Read one complete HCI event from the interrupt endpoint.

  @param[in] TimeoutMs  How long to wait for the first packet; once an event
                        has started, the rest gets up to a second.

  @retval EFI_TIMEOUT   Nothing arrived within TimeoutMs.
**/
EFI_STATUS
UsbBtReadEvent (
  IN  USB_BT_DEVICE  *Device,
  OUT UINT8          *Buffer,
  IN  UINTN          BufferSize,
  OUT UINTN          *EventLength,
  IN  UINT32         TimeoutMs
  );

/**
  Hex dump helper shared with the WMT trace callback.
**/
VOID
UsbBtDump (
  IN CONST CHAR8  *Tag,
  IN CONST UINT8  *Data,
  IN UINTN        Length,
  IN UINTN        MaxBytes
  );

#endif // USB_BT_LIB_H_
