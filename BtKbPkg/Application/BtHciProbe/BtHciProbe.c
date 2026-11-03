/** @file
  BtHciProbe: milestone 1 shell app for the MediaTek MT7922 Bluetooth
  controller.

  Default run (no options):
    1. find the Bluetooth USB interface (cached descriptors only),
    2. read chip ID / firmware version registers,
    3. parse the firmware file and ask the chip whether each section is
       loaded (status query, no firmware data sent),
    4. stop if a section is missing, unless -upload was given,
    5. turn the Bluetooth function on, HCI_Reset, read version, BD_ADDR,
       LE buffer size and local name,
    6. HCI_Reset and turn the function off again (as Linux does at shutdown),
       unless -keep was given.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: MIT OR Apache-2.0
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MtkBtLib.h>

#include <Library/UsbBtLib.h>

#define PROBE_VERSION     L"0.1"
#define DEFAULT_FW_FILE   L"BT_RAM_CODE_MT7922_1_1_hdr.bin"
#define HCI_TIMEOUT_MS    2000

typedef struct {
  BOOLEAN    List;
  BOOLEAN    ParseOnly;
  BOOLEAN    ChipIdOnly;
  BOOLEAN    AllowUpload;
  BOOLEAN    Keep;
  BOOLEAN    Verbose;
  BOOLEAN    SubsysReset;
  UINTN      Index;
  CHAR16     *FwPath;
} PROBE_OPTIONS;

typedef struct {
  BOOLEAN    Verbose;
  UINT32     LastPercent;
} PROBE_CALLBACKS;

STATIC UINT64  mTscPerUs;

STATIC
VOID
CalibrateTsc (
  VOID
  )
{
  UINT64  Start;

  Start = AsmReadTsc ();
  gBS->Stall (20000);
  mTscPerUs = DivU64x32 (AsmReadTsc () - Start, 20000);
  if (mTscPerUs == 0) {
    mTscPerUs = 1;
  }
}

STATIC
UINT32
ElapsedMs (
  IN UINT64  StartTsc
  )
{
  return (UINT32)DivU64x64Remainder (AsmReadTsc () - StartTsc, MultU64x32 (mTscPerUs, 1000), NULL);
}

STATIC
VOID
EFIAPI
TraceCallback (
  IN VOID         *Context,
  IN CONST CHAR8  *Tag,
  IN CONST UINT8  *Data,
  IN UINTN        Length
  )
{
  PROBE_CALLBACKS  *Callbacks;

  Callbacks = (PROBE_CALLBACKS *)Context;
  if (Callbacks->Verbose) {
    UsbBtDump (Tag, Data, Length, 24);
  }
}

STATIC
VOID
EFIAPI
ProgressCallback (
  IN VOID    *Context,
  IN UINT32  SectionIndex,
  IN UINT32  BytesSent,
  IN UINT32  BytesTotal
  )
{
  PROBE_CALLBACKS  *Callbacks;
  UINT32           Percent;

  Callbacks = (PROBE_CALLBACKS *)Context;
  Percent   = (UINT32)DivU64x32 (MultU64x32 (BytesSent, 100), BytesTotal);
  if ((Percent / 10 != Callbacks->LastPercent / 10) || (BytesSent == BytesTotal)) {
    Print (L"  section %u: %u / %u bytes (%u%%)\n", SectionIndex, BytesSent, BytesTotal, Percent);
  }

  Callbacks->LastPercent = Percent;
}

STATIC
VOID
PrintUsage (
  VOID
  )
{
  Print (L"BtHciProbe %s - MediaTek MT79xx Bluetooth bring-up probe\n\n", PROBE_VERSION);
  Print (L"usage: BtHciProbe [options]\n");
  Print (L"  -list          list Bluetooth USB interfaces and exit (sends nothing)\n");
  Print (L"  -parse         parse the firmware file and exit (sends nothing)\n");
  Print (L"  -chipid        read the chip ID registers and exit\n");
  Print (L"  -fw <file>     firmware file (default %s)\n", DEFAULT_FW_FILE);
  Print (L"  -upload        allow uploading firmware sections the chip reports missing\n");
  Print (L"  -keep          leave Bluetooth on at exit (default: HCI_Reset + function off)\n");
  Print (L"  -reset7922     MT7922 subsystem reset before setup (drops loaded firmware)\n");
  Print (L"  -index <n>     use the n-th MediaTek interface (default 0)\n");
  Print (L"  -v             dump WMT and HCI traffic\n");
}

STATIC
BOOLEAN
ParseOptions (
  IN  UINTN          Argc,
  IN  CHAR16         **Argv,
  OUT PROBE_OPTIONS  *Options
  )
{
  UINTN  Index;

  ZeroMem (Options, sizeof (*Options));
  Options->FwPath = DEFAULT_FW_FILE;

  for (Index = 1; Index < Argc; Index++) {
    if (StrCmp (Argv[Index], L"-list") == 0) {
      Options->List = TRUE;
    } else if (StrCmp (Argv[Index], L"-parse") == 0) {
      Options->ParseOnly = TRUE;
    } else if (StrCmp (Argv[Index], L"-chipid") == 0) {
      Options->ChipIdOnly = TRUE;
    } else if (StrCmp (Argv[Index], L"-upload") == 0) {
      Options->AllowUpload = TRUE;
    } else if (StrCmp (Argv[Index], L"-keep") == 0) {
      Options->Keep = TRUE;
    } else if (StrCmp (Argv[Index], L"-reset7922") == 0) {
      Options->SubsysReset = TRUE;
    } else if (StrCmp (Argv[Index], L"-v") == 0) {
      Options->Verbose = TRUE;
    } else if ((StrCmp (Argv[Index], L"-fw") == 0) && (Index + 1 < Argc)) {
      Options->FwPath = Argv[++Index];
    } else if ((StrCmp (Argv[Index], L"-index") == 0) && (Index + 1 < Argc)) {
      Options->Index = StrDecimalToUintn (Argv[++Index]);
    } else {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
EFI_STATUS
LoadFile (
  IN  CHAR16  *Path,
  OUT VOID    **Buffer,
  OUT UINTN   *Size
  )
{
  EFI_STATUS         Status;
  SHELL_FILE_HANDLE  File;
  UINT64             FileSize;
  UINTN              ReadSize;
  VOID               *Data;

  Status = ShellOpenFileByName (Path, &File, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ShellGetFileSize (File, &FileSize);
  if (EFI_ERROR (Status) || (FileSize == 0) || (FileSize > SIZE_16MB)) {
    ShellCloseFile (&File);
    return EFI_ERROR (Status) ? Status : EFI_BAD_BUFFER_SIZE;
  }

  Data = AllocatePool ((UINTN)FileSize);
  if (Data == NULL) {
    ShellCloseFile (&File);
    return EFI_OUT_OF_RESOURCES;
  }

  ReadSize = (UINTN)FileSize;
  Status   = ShellReadFile (File, &ReadSize, Data);
  ShellCloseFile (&File);
  if (EFI_ERROR (Status) || (ReadSize != FileSize)) {
    FreePool (Data);
    return EFI_ERROR (Status) ? Status : EFI_END_OF_FILE;
  }

  *Buffer = Data;
  *Size   = ReadSize;
  return EFI_SUCCESS;
}

STATIC
VOID
PrintInterface (
  IN UINTN          Index,
  IN USB_BT_DEVICE  *Device
  )
{
  CHAR16  *PathText;

  Print (
    L"  [%u] %04x:%04x interface %u, event EP 0x%02x (%u B), ACL in 0x%02x, out 0x%02x%s\n",
    (UINT32)Index,
    Device->VendorId,
    Device->ProductId,
    Device->InterfaceNumber,
    Device->IntInEndpoint,
    Device->IntInMaxPacket,
    Device->BulkInEndpoint,
    Device->BulkOutEndpoint,
    (Device->VendorId == MTK_BT_USB_VENDOR_ID) ? L"  (MediaTek)" : L""
    );

  PathText = ConvertDevicePathToText (DevicePathFromHandle (Device->Handle), FALSE, FALSE);
  if (PathText != NULL) {
    Print (L"      %s\n", PathText);
    FreePool (PathText);
  }
}

STATIC
VOID
PrintFirmware (
  IN CHAR16              *Path,
  IN UINTN               Size,
  IN CONST MTK_FW_IMAGE  *Fw
  )
{
  UINT32  Index;

  Print (
    L"Firmware: %s, %u bytes, build %a, platform %a, hw 0x%04x sw 0x%04x\n",
    Path,
    (UINT32)Size,
    Fw->BuildTime,
    Fw->Platform,
    Fw->HwVer,
    Fw->SwVer
    );
  for (Index = 0; Index < Fw->SectionCount; Index++) {
    Print (
      L"  section %u: type 0x%08x, offset 0x%x, load 0x%08x, %u bytes%s\n",
      Index,
      Fw->Sections[Index].SecType,
      Fw->Sections[Index].Offset,
      Fw->Sections[Index].DlAddr,
      Fw->Sections[Index].DlSize,
      (Fw->Sections[Index].DlSize == 0) ? L" (not sent)" : L""
      );
  }

  Print (L"  full upload: %u bytes in %u chunks\n", Fw->DownloadBytes, Fw->DownloadChunks);
}

STATIC
EFI_STATUS
RunHciQueries (
  IN USB_BT_DEVICE  *Device
  )
{
  EFI_STATUS  Status;
  UINT8       Ret[256];
  UINTN       RetLength;
  CHAR8       Name[249];

  RetLength = sizeof (Ret);
  Status    = UsbBtHciCommand (Device, HCI_OP_RESET, NULL, 0, Ret, &RetLength, HCI_TIMEOUT_MS);
  if (EFI_ERROR (Status) || (RetLength < 1) || (Ret[0] != 0)) {
    Print (L"HCI_Reset: failed (%r, HCI status 0x%02x)\n", Status, (RetLength >= 1) ? Ret[0] : 0xFF);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }

  Print (L"HCI_Reset: ok\n");

  RetLength = sizeof (Ret);
  Status    = UsbBtHciCommand (Device, HCI_OP_READ_LOCAL_VERSION, NULL, 0, Ret, &RetLength, HCI_TIMEOUT_MS);
  if (!EFI_ERROR (Status) && (RetLength >= 9) && (Ret[0] == 0)) {
    Print (
      L"Local version: HCI 0x%02x rev 0x%04x, LMP 0x%02x subversion 0x%04x, manufacturer 0x%04x\n",
      Ret[1],
      Ret[2] | (Ret[3] << 8),
      Ret[4],
      Ret[7] | (Ret[8] << 8),
      Ret[5] | (Ret[6] << 8)
      );
  } else {
    Print (L"Read_Local_Version: failed (%r)\n", Status);
  }

  RetLength = sizeof (Ret);
  Status    = UsbBtHciCommand (Device, HCI_OP_READ_BD_ADDR, NULL, 0, Ret, &RetLength, HCI_TIMEOUT_MS);
  if (!EFI_ERROR (Status) && (RetLength >= 7) && (Ret[0] == 0)) {
    Print (L"BD_ADDR: %02X:%02X:%02X:%02X:%02X:%02X\n", Ret[6], Ret[5], Ret[4], Ret[3], Ret[2], Ret[1]);
  } else {
    Print (L"Read_BD_ADDR: failed (%r)\n", Status);
  }

  RetLength = sizeof (Ret);
  Status    = UsbBtHciCommand (Device, HCI_OP_LE_READ_BUFFER_SIZE, NULL, 0, Ret, &RetLength, HCI_TIMEOUT_MS);
  if (!EFI_ERROR (Status) && (RetLength >= 4) && (Ret[0] == 0)) {
    Print (L"LE ACL buffers: %u x %u bytes\n", Ret[3], Ret[1] | (Ret[2] << 8));
  } else {
    Print (L"LE_Read_Buffer_Size: failed (%r)\n", Status);
  }

  RetLength = sizeof (Ret);
  Status    = UsbBtHciCommand (Device, HCI_OP_READ_LOCAL_NAME, NULL, 0, Ret, &RetLength, HCI_TIMEOUT_MS);
  if (!EFI_ERROR (Status) && (RetLength >= 2) && (Ret[0] == 0)) {
    ZeroMem (Name, sizeof (Name));
    CopyMem (Name, &Ret[1], MIN (RetLength - 1, sizeof (Name) - 1));
    Print (L"Local name: \"%a\"\n", Name);
  }

  return EFI_SUCCESS;
}

INTN
EFIAPI
ShellAppMain (
  IN UINTN   Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS          Status;
  PROBE_OPTIONS       Options;
  PROBE_CALLBACKS     Callbacks;
  USB_BT_DEVICE       *Devices;
  USB_BT_DEVICE       *Device;
  UINTN               DeviceCount;
  UINTN               Scanned;
  UINTN               Index;
  UINTN               MtkSeen;
  MTK_BT_DEVICE       Mtk;
  UINT32              ChipId;
  UINT32              FwVersion;
  UINT32              FwFlavor;
  CHAR8               ExpectedName[48];
  VOID                *FwData;
  UINTN               FwSize;
  MTK_FW_IMAGE        *Fw;
  MTK_FW_LOAD_RESULT  LoadResult;
  MTK_WMT_EVENT       Event;
  UINT64              StartTsc;
  UINT64              PhaseTsc;
  BOOLEAN             Enabled;
  INTN                Exit;

  if (!ParseOptions (Argc, Argv, &Options)) {
    PrintUsage ();
    return 2;
  }

  Print (L"BtHciProbe %s\n", PROBE_VERSION);
  CalibrateTsc ();
  StartTsc = AsmReadTsc ();

  Devices = NULL;
  Device  = NULL;
  FwData  = NULL;
  Fw      = NULL;
  Enabled = FALSE;
  Exit    = 1;

  //
  // The firmware file is only parsed here; nothing is sent to the chip.
  //
  if (!Options.List && !Options.ChipIdOnly) {
    Fw = AllocateZeroPool (sizeof (MTK_FW_IMAGE));
    if (Fw == NULL) {
      return 1;
    }

    Status = LoadFile (Options.FwPath, &FwData, &FwSize);
    if (EFI_ERROR (Status)) {
      Print (L"Cannot read firmware file %s: %r\n", Options.FwPath, Status);
      goto Done;
    }

    Status = MtkFwParse (FwData, FwSize, Fw);
    if (EFI_ERROR (Status)) {
      Print (L"Firmware file %s is not a valid MT79xx image: %r\n", Options.FwPath, Status);
      goto Done;
    }

    PrintFirmware (Options.FwPath, FwSize, Fw);
    if (Options.ParseOnly) {
      Exit = 0;
      goto Done;
    }
  }

  Status = UsbBtFindInterfaces (&Devices, &DeviceCount, &Scanned);
  if (EFI_ERROR (Status)) {
    Print (L"USB enumeration failed: %r\n", Status);
    goto Done;
  }

  Print (L"Bluetooth USB interfaces: %u (of %u USB interfaces)\n", (UINT32)DeviceCount, (UINT32)Scanned);
  MtkSeen = 0;
  for (Index = 0; Index < DeviceCount; Index++) {
    PrintInterface (Index, &Devices[Index]);
    if (Devices[Index].VendorId == MTK_BT_USB_VENDOR_ID) {
      if ((MtkSeen == Options.Index) && (Device == NULL)) {
        Device = &Devices[Index];
      }

      MtkSeen++;
    }
  }

  if (Options.List) {
    Exit = 0;
    goto Done;
  }

  if (Device == NULL) {
    Print (L"No MediaTek Bluetooth interface found (index %u).\n", (UINT32)Options.Index);
    goto Done;
  }

  Device->Verbose = Options.Verbose;
  UsbBtInitTransport (Device);
  MtkBtInitDevice (&Mtk, &Device->Transport);
  Callbacks.Verbose      = Options.Verbose;
  Callbacks.LastPercent  = 0;
  Mtk.Trace              = TraceCallback;
  Mtk.Progress           = ProgressCallback;
  Mtk.CallbackContext    = &Callbacks;

  Status = MtkBtGetChipInfo (&Mtk, &ChipId, &FwVersion, &FwFlavor);
  if (EFI_ERROR (Status)) {
    Print (L"Reading chip ID failed: %r\n", Status);
    goto Done;
  }

  Print (L"Chip: 0x%04x, firmware version register 0x%08x, flavor %u", ChipId, FwVersion, FwFlavor);
  if (!EFI_ERROR (MtkBtFirmwareName (ChipId, FwVersion, FwFlavor, ExpectedName, sizeof (ExpectedName)))) {
    Print (L", expects %a", ExpectedName);
  }

  Print (L"\n");
  if (ChipId != 0x7922) {
    Print (L"Only the MT7922 has been looked at so far; stopping.\n");
    goto Done;
  }

  if (Options.ChipIdOnly) {
    Exit = 0;
    goto Done;
  }

  if (Options.SubsysReset) {
    Print (L"MT7922 subsystem reset...\n");
    Status = MtkBtSubsysReset7922 (&Mtk);
    Print (L"  %r\n", Status);
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  }

  PhaseTsc = AsmReadTsc ();
  Status   = MtkBtLoadFirmware (&Mtk, Fw, Options.AllowUpload, &LoadResult);
  Print (
    L"Firmware sections: %u checked, %u already loaded, %u uploaded (%u chunks), %u busy retries, %u ms, %u WMT commands, %u event polls (%u flagged short)\n",
    LoadResult.SectionsChecked,
    LoadResult.SectionsAlreadyLoaded,
    LoadResult.SectionsDownloaded,
    LoadResult.ChunksSent,
    LoadResult.BusyRetries,
    ElapsedMs (PhaseTsc),
    Mtk.WmtCommands,
    Mtk.EventPolls,
    Mtk.ShortPolls
    );
  if (Status == EFI_NOT_STARTED) {
    Print (
      L"Section %d is not loaded on the chip. Nothing was uploaded; rerun with -upload to send it.\n",
      LoadResult.FirstMissingSection
      );
    goto Done;
  }

  if (EFI_ERROR (Status)) {
    Print (L"Firmware check failed: %r\n", Status);
    goto Done;
  }

  Status = MtkBtEnable (&Mtk, &Event);
  if (EFI_ERROR (Status)) {
    Print (L"Turning Bluetooth on failed: %r\n", Status);
    goto Done;
  }

  Enabled = TRUE;
  Print (L"Bluetooth function on (event flag 0x%02x", Event.Flag);
  if (Event.HasStatus) {
    Print (L", status 0x%04x", Event.Status);
  }

  Print (L")\n");

  Status = RunHciQueries (Device);
  if (!EFI_ERROR (Status)) {
    Exit = 0;
  }

Done:
  if (Enabled && !Options.Keep) {
    UsbBtHciCommand (Device, HCI_OP_RESET, NULL, 0, NULL, NULL, HCI_TIMEOUT_MS);
    Status = MtkBtDisable (&Mtk, NULL);
    Print (L"Handoff: HCI_Reset + function off: %r\n", Status);
  }

  if (Devices != NULL) {
    Print (L"Total: %u ms\n", ElapsedMs (StartTsc));
    FreePool (Devices);
  }

  if (FwData != NULL) {
    FreePool (FwData);
  }

  if (Fw != NULL) {
    FreePool (Fw);
  }

  return Exit;
}
