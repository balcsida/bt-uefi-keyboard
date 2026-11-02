/** @file
  MediaTek MT79xx Bluetooth bring-up over USB: firmware image parsing, the WMT
  vendor command channel, firmware upload and function control.

  The protocol follows what Linux btmtk does for USB parts (MT7922 tested
  against the description, not ported code):

    - WMT commands are HCI vendor command 0xFC6F, sent as a class control
      transfer like any HCI command.
    - WMT replies are vendor event 0xE4, fetched by polling a vendor control
      IN request on endpoint 0. An empty reply means "not ready yet".
    - Chip and UHW registers are read and written with vendor control
      requests.

  All I/O goes through MTK_BT_TRANSPORT, so the library runs unchanged on top
  of EFI_USB_IO_PROTOCOL and inside host-based unit tests.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MTK_BT_LIB_H_
#define MTK_BT_LIB_H_

#include <Uefi.h>
#include <Protocol/UsbIo.h>

//
// USB identity. Linux matches every MediaTek Bluetooth part by vendor plus
// interface class Wireless / RF / Bluetooth (E0/01/01).
//
#define MTK_BT_USB_VENDOR_ID      0x0E8D
#define MTK_BT_USB_CLASS          0xE0
#define MTK_BT_USB_SUBCLASS       0x01
#define MTK_BT_USB_PROTOCOL       0x01

//
// Chip identification registers (vendor request 0x63).
//
#define MTK_BT_REG_CHIP_ID_LEGACY  0x80000008   // MT7663 reports its ID here
#define MTK_BT_REG_CHIP_ID         0x70010200
#define MTK_BT_REG_FW_VERSION      0x80021004
#define MTK_BT_REG_FW_FLAVOR       0x70010020

//
// UHW registers (vendor requests 0x01 / 0x02).
//
#define MTK_BT_UHW_MISC            0x70002510
#define MTK_BT_UHW_SUBSYS_RST      0x70002610
#define MTK_BT_UHW_UDMA_INT_STA    0x74000024
#define MTK_BT_UHW_EP_RST_OPT      0x74011890
#define MTK_BT_UHW_EP_RST_IN_OUT   0x00010001
#define MTK_BT_UHW_RST_DONE        BIT8

//
// WMT protocol.
//
#define MTK_WMT_HCI_OPCODE          0xFC6F
#define MTK_WMT_EVENT_CODE          0xE4
#define MTK_WMT_DIR_HOST_TO_CHIP    0x01
#define MTK_WMT_HEADER_SIZE         5       // dir, op, dlen (LE16), flag
#define MTK_WMT_MAX_PAYLOAD         250     // 255-byte HCI parameter limit - header
#define MTK_WMT_EVENT_BUFFER_SIZE   64

#define MTK_WMT_OP_PATCH_DOWNLOAD   0x01
#define MTK_WMT_OP_FUNC_CTRL        0x06

#define MTK_WMT_PATCH_QUERY         0x00    // flag on the per-section query
#define MTK_WMT_PATCH_FIRST         0x01    // flags on data chunks
#define MTK_WMT_PATCH_CONTINUE      0x02
#define MTK_WMT_PATCH_LAST          0x03

//
// Firmware image layout (BT_RAM_CODE_MT79xx_*_hdr.bin).
//
#define MTK_FW_HEADER_SIZE          32
#define MTK_FW_GLOBAL_DESC_SIZE     64
#define MTK_FW_SECTION_MAP_SIZE     64
#define MTK_FW_SECTION_COMMON_SIZE  12      // sectype, secoffset, secsize
#define MTK_FW_BIN_INFO_SIZE        52      // the block sent with the section query
#define MTK_FW_MAX_SECTIONS         16

typedef struct {
  UINT32         SecType;
  UINT32         Offset;          ///< File offset of the section payload
  UINT32         Size;            ///< Payload size in the file
  UINT32         DlAddr;          ///< Load address on the chip
  UINT32         DlSize;          ///< Bytes to download; 0 means "not sent"
  UINT32         BinType;
  UINT32         DlModeCrcType;
  UINT32         Crc;
  CONST UINT8    *BinInfo;        ///< MTK_FW_BIN_INFO_SIZE bytes inside the image
  CONST UINT8    *Data;           ///< DlSize bytes inside the image
} MTK_FW_SECTION;

typedef struct {
  CHAR8             BuildTime[17];  ///< NUL-terminated, e.g. "20260724143815"
  CHAR8             Platform[5];    ///< NUL-terminated, e.g. "ALPS"
  UINT16            HwVer;
  UINT16            SwVer;
  UINT32            Magic;
  UINT32            SectionCount;
  UINT32            DownloadBytes;  ///< Sum of DlSize over all sections
  UINT32            DownloadChunks; ///< WMT chunk commands a full upload needs
  MTK_FW_SECTION    Sections[MTK_FW_MAX_SECTIONS];
} MTK_FW_IMAGE;

typedef struct _MTK_BT_TRANSPORT MTK_BT_TRANSPORT;

/**
  Perform a control transfer on endpoint 0.

  Like EFI_USB_IO_PROTOCOL.UsbControlTransfer, the number of bytes actually
  received is NOT reported, so callers that must detect an empty IN reply
  pre-fill the buffer. A short IN transfer is NOT an error: return EFI_SUCCESS
  and set *Short to TRUE if the USB stack says the reply was short (EDK2's
  UsbBusDxe reports it as EFI_DEVICE_ERROR with no USB error bits). Stacks
  that do not tell leave *Short FALSE.
**/
typedef
EFI_STATUS
(EFIAPI *MTK_BT_CONTROL_TRANSFER)(
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
  );

typedef
VOID
(EFIAPI *MTK_BT_STALL)(
  IN MTK_BT_TRANSPORT  *This,
  IN UINTN             Microseconds
  );

/**
  Optional traffic trace: Tag is "wmt>" for commands, "wmt<" for events, etc.
**/
typedef
VOID
(EFIAPI *MTK_BT_TRACE)(
  IN VOID         *Context,
  IN CONST CHAR8  *Tag,
  IN CONST UINT8  *Data,
  IN UINTN        Length
  );

/**
  Optional upload progress: called after every chunk.
**/
typedef
VOID
(EFIAPI *MTK_BT_PROGRESS)(
  IN VOID    *Context,
  IN UINT32  SectionIndex,
  IN UINT32  BytesSent,
  IN UINT32  BytesTotal
  );

struct _MTK_BT_TRANSPORT {
  MTK_BT_CONTROL_TRANSFER    ControlTransfer;
  MTK_BT_STALL               Stall;
};

typedef struct {
  MTK_BT_TRANSPORT    *Transport;
  UINT32              EventTimeoutMs;   ///< Per WMT command; Linux uses 10 s
  UINT32              PollIntervalUs;   ///< Between empty event polls; Linux uses 500
  MTK_BT_TRACE        Trace;            ///< Optional
  MTK_BT_PROGRESS     Progress;         ///< Optional
  VOID                *CallbackContext;
  //
  // Statistics, updated by the library.
  //
  UINT32              WmtCommands;
  UINT32              EventPolls;
  UINT32              ShortPolls;       ///< Polls the USB stack flagged as short
} MTK_BT_DEVICE;

typedef struct {
  UINT8      Op;
  UINT8      Flag;
  UINT8      Length;       ///< Total event length: 2 + parameter length
  BOOLEAN    HasStatus;
  UINT16     Status;       ///< Big-endian word after the WMT header, if present
  UINT8      Raw[MTK_WMT_EVENT_BUFFER_SIZE];
} MTK_WMT_EVENT;

typedef enum {
  MtkSectionNeedsDownload,
  MtkSectionBusy,
  MtkSectionLoaded
} MTK_SECTION_STATE;

typedef struct {
  UINT32    SectionsChecked;
  UINT32    SectionsAlreadyLoaded;
  UINT32    SectionsDownloaded;
  UINT32    ChunksSent;
  UINT32    BusyRetries;
  INT32     FirstMissingSection;   ///< -1 if none; set when download was not allowed
} MTK_FW_LOAD_RESULT;

/**
  Fill in default timeouts. Transport must be set by the caller.
**/
VOID
EFIAPI
MtkBtInitDevice (
  OUT MTK_BT_DEVICE     *Device,
  IN  MTK_BT_TRANSPORT  *Transport
  );

/**
  Parse and bounds-check a firmware image. Fw keeps pointers into Image.

  @retval EFI_SUCCESS             Image is well formed.
  @retval EFI_INVALID_PARAMETER   NULL pointer.
  @retval EFI_VOLUME_CORRUPTED    Truncated image or out-of-range section.
  @retval EFI_UNSUPPORTED         More sections than MTK_FW_MAX_SECTIONS.
**/
EFI_STATUS
EFIAPI
MtkFwParse (
  IN  CONST VOID    *Image,
  IN  UINTN         ImageSize,
  OUT MTK_FW_IMAGE  *Fw
  );

/**
  Build the firmware file name Linux would request for this chip, for example
  "BT_RAM_CODE_MT7922_1_1_hdr.bin". Only the MT7922/MT7961/MT7902 naming
  scheme is supported.

  @retval EFI_UNSUPPORTED        Unknown chip.
  @retval EFI_BUFFER_TOO_SMALL   Buffer too small.
**/
EFI_STATUS
EFIAPI
MtkBtFirmwareName (
  IN  UINT32  ChipId,
  IN  UINT32  FwVersion,
  IN  UINT32  FwFlavor,
  OUT CHAR8   *Buffer,
  IN  UINTN   BufferSize
  );

EFI_STATUS
EFIAPI
MtkBtReadChipReg (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT32         Reg,
  OUT UINT32         *Value
  );

EFI_STATUS
EFIAPI
MtkBtReadUhwReg (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT32         Reg,
  OUT UINT32         *Value
  );

EFI_STATUS
EFIAPI
MtkBtWriteUhwReg (
  IN MTK_BT_DEVICE  *Device,
  IN UINT32         Reg,
  IN UINT32         Value
  );

/**
  Read chip ID, firmware version and flavor (read-only register accesses).
**/
EFI_STATUS
EFIAPI
MtkBtGetChipInfo (
  IN  MTK_BT_DEVICE  *Device,
  OUT UINT32         *ChipId,
  OUT UINT32         *FwVersion,
  OUT UINT32         *FwFlavor
  );

/**
  Send one WMT command and wait for its event.

  @retval EFI_TIMEOUT          No event within Device->EventTimeoutMs.
  @retval EFI_PROTOCOL_ERROR   Event for a different op, or malformed event.
**/
EFI_STATUS
EFIAPI
MtkBtWmtCommand (
  IN  MTK_BT_DEVICE  *Device,
  IN  UINT8          Op,
  IN  UINT8          Flag,
  IN  CONST VOID     *Payload OPTIONAL,
  IN  UINT16         PayloadLength,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  );

/**
  Ask the chip whether one firmware section is loaded. This is a status
  query; it does not send any firmware data.
**/
EFI_STATUS
EFIAPI
MtkBtQuerySection (
  IN  MTK_BT_DEVICE         *Device,
  IN  CONST MTK_FW_SECTION  *Section,
  OUT MTK_SECTION_STATE     *State
  );

/**
  Send one section's data in chunks. Call only after MtkBtQuerySection
  returned MtkSectionNeedsDownload for the same section.
**/
EFI_STATUS
EFIAPI
MtkBtDownloadSection (
  IN     MTK_BT_DEVICE         *Device,
  IN     CONST MTK_FW_SECTION  *Section,
  IN     UINT32                SectionIndex,
  IN OUT MTK_FW_LOAD_RESULT    *Result
  );

/**
  Query every section and, if AllowDownload is TRUE, upload the missing ones.
  Waits 100 ms for firmware activation at the end, as Linux does.

  @retval EFI_SUCCESS       All sections are loaded on the chip.
  @retval EFI_NOT_STARTED   A section needs downloading and AllowDownload is
                            FALSE. Nothing was uploaded; see
                            Result->FirstMissingSection.
  @retval EFI_TIMEOUT       The chip stayed busy for 20 queries.
**/
EFI_STATUS
EFIAPI
MtkBtLoadFirmware (
  IN  MTK_BT_DEVICE         *Device,
  IN  CONST MTK_FW_IMAGE    *Fw,
  IN  BOOLEAN               AllowDownload,
  OUT MTK_FW_LOAD_RESULT    *Result
  );

/**
  Set the endpoint reset option and turn the Bluetooth function on
  (WMT FUNC_CTRL 1). Standard HCI works after this.
**/
EFI_STATUS
EFIAPI
MtkBtEnable (
  IN  MTK_BT_DEVICE  *Device,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  );

/**
  Turn the Bluetooth function off (WMT FUNC_CTRL 0), as Linux does at
  shutdown.
**/
EFI_STATUS
EFIAPI
MtkBtDisable (
  IN  MTK_BT_DEVICE  *Device,
  OUT MTK_WMT_EVENT  *Event OPTIONAL
  );

/**
  MT7922 Bluetooth subsystem reset, for recovery after a WMT timeout.
  Probably discards the loaded firmware (untested), so a full upload follows.
**/
EFI_STATUS
EFIAPI
MtkBtSubsysReset7922 (
  IN MTK_BT_DEVICE  *Device
  );

#endif // MTK_BT_LIB_H_
