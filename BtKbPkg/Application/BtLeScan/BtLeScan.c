/** @file
  BtLeScan: milestone 2 shell app. Brings up the MediaTek controller (no
  firmware upload unless -upload), starts the NimBLE host on top of it and
  runs an LE scan, reporting every advertiser and whether the bonded
  keyboard showed up.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MtkBtLib.h>
#include <Library/NimbleHostLib.h>
#include <Library/UsbBtLib.h>

#define SCAN_VERSION       L"0.1"
#define DEFAULT_FW_FILE    L"BT_RAM_CODE_MT7922_1_1_hdr.bin"
#define DEFAULT_SECONDS    30
#define SYNC_TIMEOUT_MS    5000
#define MAX_DEVICES        64
#define POLL_FIRST_MS      1
#define POLL_MAX_EVENTS    8

typedef struct {
  UINT8      Address[6];
  UINT8      AddressType;
  UINT32     Reports;
  UINT8      EventTypes;      ///< Bit n set when event type n was seen
  INT8       Rssi;
  CHAR8      Name[32];
  BOOLEAN    HidService;
  BOOLEAN    HasAppearance;
  UINT16     Appearance;
} SEEN_DEVICE;

typedef struct {
  USB_BT_DEVICE    *Usb;
  BOOLEAN          Verbose;
  BOOLEAN          All;
  UINT8            Target[6];   ///< Little-endian, as in reports
  BOOLEAN          HaveTarget;
  SEEN_DEVICE      Devices[MAX_DEVICES];
  UINTN            DeviceCount;
  UINT32           TotalReports;
  UINT32           TargetPrinted;
  UINT8            Event[HCI_MAX_EVENT_SIZE + 64];
} SCAN_STATE;

STATIC UINT64      mTscPerMs;
STATIC UINT64      mTscStart;

STATIC
VOID
CalibrateTsc (
  VOID
  )
{
  UINT64  Start;

  Start = AsmReadTsc ();
  gBS->Stall (20000);
  mTscPerMs = DivU64x32 (AsmReadTsc () - Start, 20);
  if (mTscPerMs == 0) {
    mTscPerMs = 1;
  }

  mTscStart = AsmReadTsc ();
}

STATIC
UINT32
NowMs (
  VOID
  )
{
  return (UINT32)DivU64x64Remainder (AsmReadTsc () - mTscStart, mTscPerMs, NULL);
}

//
// NimBLE transport callbacks
//

STATIC
EFI_STATUS
EFIAPI
HciSendCommand (
  IN VOID         *Context,
  IN CONST UINT8  *Packet,
  IN UINTN        Length
  )
{
  return UsbBtSendCommand (((SCAN_STATE *)Context)->Usb, Packet, Length);
}

STATIC
EFI_STATUS
EFIAPI
HciSendAcl (
  IN VOID         *Context,
  IN CONST UINT8  *Packet,
  IN UINTN        Length
  )
{
  return UsbBtSendAcl (((SCAN_STATE *)Context)->Usb, Packet, Length);
}

STATIC
VOID
EFIAPI
HciPoll (
  IN VOID  *Context
  )
{
  SCAN_STATE  *State;
  EFI_STATUS  Status;
  UINTN       Length;
  UINTN       Count;

  State = (SCAN_STATE *)Context;
  for (Count = 0; Count < POLL_MAX_EVENTS; Count++) {
    Status = UsbBtReadEvent (State->Usb, State->Event, sizeof (State->Event), &Length, POLL_FIRST_MS);
    if (EFI_ERROR (Status)) {
      if (Status != EFI_TIMEOUT) {
        Print (L"  event read failed: %r\n", Status);
      }

      return;
    }

    if (State->Verbose) {
      UsbBtDump ("hci<", State->Event, Length, 24);
    }

    if (EFI_ERROR (NimbleHostDeliverEvent (State->Event, Length)) && State->Verbose) {
      Print (L"  (event 0x%02x dropped)\n", State->Event[0]);
    }
  }
}

STATIC
UINT32
EFIAPI
HciNowMs (
  IN VOID  *Context
  )
{
  return NowMs ();
}

STATIC
VOID
EFIAPI
HciLog (
  IN VOID         *Context,
  IN CONST CHAR8  *Line
  )
{
  Print (L"  nimble: %a\n", Line);
}

//
// Reports
//

STATIC CONST CHAR16  *mEventTypeNames[] = {
  L"ADV_IND", L"ADV_DIRECT_IND", L"ADV_SCAN_IND", L"ADV_NONCONN_IND", L"SCAN_RSP"
};

STATIC
CONST CHAR16 *
EventTypeName (
  IN UINT8  Type
  )
{
  return (Type < ARRAY_SIZE (mEventTypeNames)) ? mEventTypeNames[Type] : L"?";
}

STATIC
CONST CHAR16 *
AddressTypeName (
  IN UINT8  Type
  )
{
  switch (Type) {
    case 0:
      return L"public";
    case 1:
      return L"random";
    case 2:
      return L"public id";
    case 3:
      return L"random id";
    default:
      return L"?";
  }
}

STATIC
VOID
PrintAddress (
  IN CONST UINT8  *Address
  )
{
  Print (L"%02X:%02X:%02X:%02X:%02X:%02X", Address[5], Address[4], Address[3], Address[2], Address[1], Address[0]);
}

STATIC
BOOLEAN
ParseAddress (
  IN  CONST CHAR16  *Text,
  OUT UINT8         *Address
  )
{
  UINTN   Index;
  UINTN   Digit;
  UINT8   Value;
  CHAR16  Ch;

  //
  // "C0:00:00:00:00:01" -> little-endian bytes.
  //
  if (StrLen (Text) != 17) {
    return FALSE;
  }

  for (Index = 0; Index < 6; Index++) {
    Value = 0;
    for (Digit = 0; Digit < 2; Digit++) {
      Ch = Text[Index * 3 + Digit];
      if ((Ch >= L'0') && (Ch <= L'9')) {
        Value = (UINT8)(Value * 16 + (Ch - L'0'));
      } else if ((Ch >= L'A') && (Ch <= L'F')) {
        Value = (UINT8)(Value * 16 + (Ch - L'A' + 10));
      } else if ((Ch >= L'a') && (Ch <= L'f')) {
        Value = (UINT8)(Value * 16 + (Ch - L'a' + 10));
      } else {
        return FALSE;
      }
    }

    if ((Index < 5) && (Text[Index * 3 + 2] != L':')) {
      return FALSE;
    }

    Address[5 - Index] = Value;
  }

  return TRUE;
}

STATIC
VOID
PrintDeviceLine (
  IN CONST CHAR16             *Prefix,
  IN CONST NIMBLE_HOST_ADV_REPORT  *Report,
  IN BOOLEAN                  IsTarget
  )
{
  Print (L"%s", Prefix);
  PrintAddress (Report->Address);
  Print (L" (%s) %4d dBm  %s", AddressTypeName (Report->AddressType), Report->Rssi, EventTypeName (Report->EventType));
  if (Report->Name[0] != '\0') {
    Print (L"  \"%a\"", Report->Name);
  }

  if (Report->HidService) {
    Print (L"  HID");
  }

  if (Report->HasAppearance) {
    Print (L"  appearance 0x%04x", Report->Appearance);
  }

  if (IsTarget) {
    Print (L"   <== bonded keyboard");
  }

  Print (L"\n");
}

STATIC
VOID
EFIAPI
OnReport (
  IN VOID                          *Context,
  IN CONST NIMBLE_HOST_ADV_REPORT  *Report
  )
{
  SCAN_STATE   *State;
  SEEN_DEVICE  *Device;
  UINTN        Index;
  BOOLEAN      IsTarget;
  BOOLEAN      IsNew;

  State = (SCAN_STATE *)Context;
  State->TotalReports++;
  IsTarget = State->HaveTarget && (CompareMem (Report->Address, State->Target, 6) == 0);

  Device = NULL;
  for (Index = 0; Index < State->DeviceCount; Index++) {
    if ((CompareMem (State->Devices[Index].Address, Report->Address, 6) == 0) &&
        (State->Devices[Index].AddressType == Report->AddressType))
    {
      Device = &State->Devices[Index];
      break;
    }
  }

  IsNew = (Device == NULL);
  if (IsNew && (State->DeviceCount < MAX_DEVICES)) {
    Device = &State->Devices[State->DeviceCount++];
    ZeroMem (Device, sizeof (*Device));
    CopyMem (Device->Address, Report->Address, 6);
    Device->AddressType = Report->AddressType;
  }

  if (Device != NULL) {
    Device->Reports++;
    Device->Rssi = Report->Rssi;
    if (Report->EventType < 8) {
      Device->EventTypes |= (UINT8)(1 << Report->EventType);
    }

    if ((Report->Name[0] != '\0') && (Device->Name[0] == '\0')) {
      CopyMem (Device->Name, Report->Name, sizeof (Device->Name));
    }

    Device->HidService |= Report->HidService;
    if (Report->HasAppearance) {
      Device->HasAppearance = TRUE;
      Device->Appearance    = Report->Appearance;
    }
  }

  if (IsTarget && (State->TargetPrinted < 5)) {
    State->TargetPrinted++;
    PrintDeviceLine (L"  * ", Report, TRUE);
    if (State->Verbose) {
      UsbBtDump ("data:", Report->Data, Report->DataLength, 31);
    }
  } else if (IsNew || State->All) {
    PrintDeviceLine (IsNew ? L"  + " : L"    ", Report, IsTarget);
  }
}

STATIC
VOID
PrintSummary (
  IN SCAN_STATE  *State
  )
{
  UINTN        Index;
  UINT8        Type;
  SEEN_DEVICE  *Device;
  BOOLEAN      TargetSeen;

  Print (L"\nScan summary: %u reports from %u devices\n", State->TotalReports, (UINT32)State->DeviceCount);
  TargetSeen = FALSE;
  for (Index = 0; Index < State->DeviceCount; Index++) {
    Device = &State->Devices[Index];
    Print (L"  ");
    PrintAddress (Device->Address);
    Print (L" (%s) %4u reports, last %4d dBm,", AddressTypeName (Device->AddressType), Device->Reports, Device->Rssi);
    for (Type = 0; Type < ARRAY_SIZE (mEventTypeNames); Type++) {
      if ((Device->EventTypes & (1 << Type)) != 0) {
        Print (L" %s", mEventTypeNames[Type]);
      }
    }

    if (Device->Name[0] != '\0') {
      Print (L"  \"%a\"", Device->Name);
    }

    if (Device->HidService) {
      Print (L"  HID");
    }

    if (State->HaveTarget && (CompareMem (Device->Address, State->Target, 6) == 0)) {
      Print (L"   <== bonded keyboard");
      TargetSeen = TRUE;
    }

    Print (L"\n");
  }

  if (State->HaveTarget) {
    Print (L"Bonded keyboard ");
    PrintAddress (State->Target);
    Print (TargetSeen ? L": SEEN\n" : L": not seen (press a key on it during the scan)\n");
  }
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
PrintUsage (
  VOID
  )
{
  Print (L"BtLeScan %s - LE scan through NimBLE on a MediaTek MT79xx controller\n\n", SCAN_VERSION);
  Print (L"usage: BtLeScan [options]\n");
  Print (L"  -t <seconds>   scan time (default %u)\n", DEFAULT_SECONDS);
  Print (L"  -active        active scan (asks for scan responses, often with names)\n");
  Print (L"  -addr <addr>   bonded device to look for (default C0:00:00:00:00:01)\n");
  Print (L"  -all           print every report, not just new devices\n");
  Print (L"  -fw <file>     firmware file (default %s)\n", DEFAULT_FW_FILE);
  Print (L"  -upload        allow uploading firmware sections the chip reports missing\n");
  Print (L"  -keep          leave Bluetooth on at exit\n");
  Print (L"  -v             dump HCI traffic and NimBLE log\n");
  Print (L"Any key stops the scan early.\n");
}

INTN
EFIAPI
ShellAppMain (
  IN UINTN   Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS          Status;
  SCAN_STATE          *State;
  USB_BT_DEVICE       *Devices;
  UINTN               DeviceCount;
  UINTN               Scanned;
  UINTN               Index;
  MTK_BT_DEVICE       Mtk;
  UINT32              ChipId;
  UINT32              FwVersion;
  UINT32              FwFlavor;
  CHAR16              *FwPath;
  VOID                *FwData;
  UINTN               FwSize;
  MTK_FW_IMAGE        *Fw;
  MTK_FW_LOAD_RESULT  LoadResult;
  NIMBLE_HOST_HCI     Hci;
  NIMBLE_HOST_STATS   Stats;
  UINT32              Seconds;
  BOOLEAN             Active;
  BOOLEAN             AllowUpload;
  BOOLEAN             Keep;
  BOOLEAN             Enabled;
  UINT32              Start;
  UINT8               Address[6];
  EFI_INPUT_KEY       Key;
  INTN                Exit;

  State = AllocateZeroPool (sizeof (SCAN_STATE));
  Fw    = AllocateZeroPool (sizeof (MTK_FW_IMAGE));
  if ((State == NULL) || (Fw == NULL)) {
    return 1;
  }

  Seconds     = DEFAULT_SECONDS;
  Active      = FALSE;
  AllowUpload = FALSE;
  Keep        = FALSE;
  FwPath      = DEFAULT_FW_FILE;
  ParseAddress (L"C0:00:00:00:00:01", State->Target);
  State->HaveTarget = TRUE;

  for (Index = 1; Index < Argc; Index++) {
    if ((StrCmp (Argv[Index], L"-t") == 0) && (Index + 1 < Argc)) {
      Seconds = (UINT32)StrDecimalToUintn (Argv[++Index]);
    } else if (StrCmp (Argv[Index], L"-active") == 0) {
      Active = TRUE;
    } else if ((StrCmp (Argv[Index], L"-addr") == 0) && (Index + 1 < Argc)) {
      if (!ParseAddress (Argv[++Index], State->Target)) {
        PrintUsage ();
        return 2;
      }
    } else if (StrCmp (Argv[Index], L"-all") == 0) {
      State->All = TRUE;
    } else if ((StrCmp (Argv[Index], L"-fw") == 0) && (Index + 1 < Argc)) {
      FwPath = Argv[++Index];
    } else if (StrCmp (Argv[Index], L"-upload") == 0) {
      AllowUpload = TRUE;
    } else if (StrCmp (Argv[Index], L"-keep") == 0) {
      Keep = TRUE;
    } else if (StrCmp (Argv[Index], L"-v") == 0) {
      State->Verbose = TRUE;
    } else {
      PrintUsage ();
      return 2;
    }
  }

  Print (L"BtLeScan %s\n", SCAN_VERSION);
  CalibrateTsc ();
  Exit    = 1;
  Enabled = FALSE;
  Devices = NULL;
  FwData  = NULL;

  //
  // Controller bring-up, as in BtHciProbe.
  //
  Status = UsbBtFindInterfaces (&Devices, &DeviceCount, &Scanned);
  if (EFI_ERROR (Status) || (DeviceCount == 0)) {
    Print (L"No Bluetooth HCI interface found (%u USB interfaces scanned).\n", (UINT32)Scanned);
    goto Done;
  }

  for (Index = 0; Index < DeviceCount; Index++) {
    if (Devices[Index].VendorId == MTK_BT_USB_VENDOR_ID) {
      State->Usb = &Devices[Index];
      break;
    }
  }

  if (State->Usb == NULL) {
    Print (L"No MediaTek Bluetooth interface found.\n");
    goto Done;
  }

  State->Usb->Verbose = State->Verbose;
  UsbBtInitTransport (State->Usb);
  MtkBtInitDevice (&Mtk, &State->Usb->Transport);

  Status = MtkBtGetChipInfo (&Mtk, &ChipId, &FwVersion, &FwFlavor);
  if (EFI_ERROR (Status) || (ChipId != 0x7922)) {
    Print (L"Unexpected chip 0x%04x (%r); only the MT7922 has been looked at.\n", ChipId, Status);
    goto Done;
  }

  Status = LoadFile (FwPath, &FwData, &FwSize);
  if (!EFI_ERROR (Status)) {
    Status = MtkFwParse (FwData, FwSize, Fw);
  }

  if (EFI_ERROR (Status)) {
    Print (L"Firmware file %s unusable: %r\n", FwPath, Status);
    goto Done;
  }

  Status = MtkBtLoadFirmware (&Mtk, Fw, AllowUpload, &LoadResult);
  if (Status == EFI_NOT_STARTED) {
    Print (L"Firmware section %d is not loaded; nothing uploaded. Rerun with -upload.\n", LoadResult.FirstMissingSection);
    goto Done;
  }

  if (EFI_ERROR (Status)) {
    Print (L"Firmware check failed: %r\n", Status);
    goto Done;
  }

  Print (
    L"Chip 0x%04x: %u/%u firmware sections already loaded, %u uploaded\n",
    ChipId,
    LoadResult.SectionsAlreadyLoaded,
    LoadResult.SectionsChecked,
    LoadResult.SectionsDownloaded
    );

  Status = MtkBtEnable (&Mtk, NULL);
  if (EFI_ERROR (Status)) {
    Print (L"Turning Bluetooth on failed: %r\n", Status);
    goto Done;
  }

  Enabled = TRUE;

  //
  // NimBLE host on top.
  //
  ZeroMem (&Hci, sizeof (Hci));
  Hci.SendCommand = HciSendCommand;
  Hci.SendAcl     = HciSendAcl;
  Hci.Poll        = HciPoll;
  Hci.NowMs       = HciNowMs;
  Hci.Log         = HciLog;
  Hci.LogLevel    = State->Verbose ? NIMBLE_HOST_LOG_INFO : NIMBLE_HOST_LOG_WARN;
  Hci.Context     = State;

  Status = NimbleHostInit (&Hci);
  if (EFI_ERROR (Status)) {
    Print (L"NimBLE init failed: %r\n", Status);
    goto Done;
  }

  Start = NowMs ();
  while (!NimbleHostSynced () && (NowMs () - Start < SYNC_TIMEOUT_MS)) {
    NimbleHostRun ();
  }

  if (!NimbleHostSynced ()) {
    Print (L"NimBLE host did not sync with the controller (reset reason %d).\n", NimbleHostResetReason ());
    goto Done;
  }

  Print (L"NimBLE host synced in %u ms", NowMs () - Start);
  if (!EFI_ERROR (NimbleHostGetPublicAddress (Address))) {
    Print (L", public address ");
    PrintAddress (Address);
  }

  Print (L"\n");

  Status = NimbleHostStartScan (Active, Seconds * 1000, OnReport, State);
  if (EFI_ERROR (Status)) {
    Print (L"Starting the scan failed: %r\n", Status);
    goto Done;
  }

  Print (L"Scanning (%s) for %u s. Press a key on the Bluetooth keyboard to wake it; any key here stops.\n", Active ? L"active" : L"passive", Seconds);
  while (NimbleHostScanning ()) {
    NimbleHostRun ();
    if (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) {
      NimbleHostStopScan ();
      Print (L"Stopped by key press.\n");
    }
  }

  PrintSummary (State);
  NimbleHostGetStats (&Stats);
  Print (
    L"Host stats: %u commands, %u events delivered, %u dropped, %u polls\n",
    Stats.CommandsSent,
    Stats.EventsDelivered,
    Stats.EventsDropped,
    Stats.Polls
    );
  Exit = 0;

Done:
  if (Enabled && !Keep) {
    UsbBtHciCommand (State->Usb, HCI_OP_RESET, NULL, 0, NULL, NULL, 2000);
    Status = MtkBtDisable (&Mtk, NULL);
    Print (L"Handoff: HCI_Reset + function off: %r\n", Status);
  }

  //
  // Nothing calls back into NimBLE once this returns (no timers or async USB
  // transfers were registered), so everything can go.
  //
  if (FwData != NULL) {
    FreePool (FwData);
  }

  if (Devices != NULL) {
    FreePool (Devices);
  }

  FreePool (Fw);
  FreePool (State);
  return Exit;
}
