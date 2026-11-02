/** @file
  Host-based unit tests for MtkBtLib against a simulated MT7922.

  Run:  MtkBtLibUnitTestHost [path/to/BT_RAM_CODE_MT7922_1_1_hdr.bin]
  With a path, the real firmware image is parsed and fully "uploaded" to the
  simulator, which checks every chunk against the file.

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>
#include <Library/MtkBtLib.h>

#include "MtkBtSim.h"

#define UNIT_TEST_APP_NAME     "MtkBtLib unit tests"
#define UNIT_TEST_APP_VERSION  "0.1"

//
// Host C runtime (this is a HOST_APPLICATION). Declared here rather than
// including <stdio.h> next to the MdePkg headers.
//
typedef struct _HOST_FILE HOST_FILE;
extern HOST_FILE *
fopen (
  CONST CHAR8  *Path,
  CONST CHAR8  *Mode
  );

extern UINTN
fread (
  VOID       *Buffer,
  UINTN      Size,
  UINTN      Count,
  HOST_FILE  *File
  );

extern INT32
fclose (
  HOST_FILE  *File
  );

STATIC CONST CHAR8  *mFirmwarePath = NULL;

//
// Synthetic image: three downloadable sections that exercise the chunk flag
// rules (several chunks; one chunk plus one byte; a single chunk) and one
// info section that is never sent.
//
#define SYN_SECTIONS   4
#define SYN_MAPS_END   (MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE + SYN_SECTIONS * MTK_FW_SECTION_MAP_SIZE)
#define SYN_SEC0_SIZE  1000
#define SYN_SEC1_SIZE  251
#define SYN_SEC2_SIZE  100
#define SYN_INFO_SIZE  16
#define SYN_IMAGE_SIZE (SYN_MAPS_END + SYN_SEC0_SIZE + SYN_SEC1_SIZE + SYN_SEC2_SIZE + SYN_INFO_SIZE)

STATIC UINT8         mSynImage[SYN_IMAGE_SIZE];
STATIC CONST UINT32  mSynSize[SYN_SECTIONS]   = { SYN_SEC0_SIZE, SYN_SEC1_SIZE, SYN_SEC2_SIZE, SYN_INFO_SIZE };
STATIC CONST UINT32  mSynDlSize[SYN_SECTIONS] = { SYN_SEC0_SIZE, SYN_SEC1_SIZE, SYN_SEC2_SIZE, 0 };
STATIC CONST UINT32  mSynDlAddr[SYN_SECTIONS] = { 0x00900000, 0x0091C000, 0x00A00000, 0 };
STATIC UINT32        mSynOffset[SYN_SECTIONS];

STATIC
VOID
PutLe32 (
  OUT UINT8   *Ptr,
  IN  UINT32  Value
  )
{
  Ptr[0] = (UINT8)Value;
  Ptr[1] = (UINT8)(Value >> 8);
  Ptr[2] = (UINT8)(Value >> 16);
  Ptr[3] = (UINT8)(Value >> 24);
}

STATIC
VOID
BuildSyntheticImage (
  VOID
  )
{
  UINT32  Index;
  UINT32  Byte;
  UINT32  Offset;
  UINT8   *Map;

  ZeroMem (mSynImage, sizeof (mSynImage));
  CopyMem (mSynImage, "20260101120000", 14);
  CopyMem (mSynImage + 16, "ALPS", 4);
  mSynImage[20] = 0x8A;
  mSynImage[22] = 0x8A;
  PutLe32 (mSynImage + 24, 0xFFFFFFFF);
  PutLe32 (mSynImage + MTK_FW_HEADER_SIZE + 12, SYN_SECTIONS);

  Offset = SYN_MAPS_END;
  for (Index = 0; Index < SYN_SECTIONS; Index++) {
    mSynOffset[Index] = Offset;
    Map               = mSynImage + MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE + Index * MTK_FW_SECTION_MAP_SIZE;
    PutLe32 (Map + 0, (Index == SYN_SECTIONS - 1) ? 0x1 : 0x00010002 + Index * 0x00020000);
    PutLe32 (Map + 4, Offset);
    PutLe32 (Map + 8, mSynSize[Index]);
    PutLe32 (Map + 12, mSynDlAddr[Index]);
    PutLe32 (Map + 16, mSynDlSize[Index]);
    PutLe32 (Map + 12 + 24, 0x12340000 + Index);    // CRC field

    for (Byte = 0; Byte < mSynSize[Index]; Byte++) {
      mSynImage[Offset + Byte] = (UINT8)(Byte * 7 + Index * 31 + 1);
    }

    Offset += mSynSize[Index];
  }
}

STATIC
VOID
SimWithSyntheticSections (
  OUT MTK_SIM  *Sim,
  IN  BOOLEAN  Loaded
  )
{
  UINT32  Index;

  MtkSimInit (Sim);
  for (Index = 0; Index < SYN_SECTIONS; Index++) {
    if (mSynDlSize[Index] != 0) {
      MtkSimAddSection (Sim, mSynDlAddr[Index], mSynDlSize[Index], mSynImage + mSynOffset[Index], Loaded);
    }
  }
}

UNIT_TEST_STATUS
EFIAPI
ParseSyntheticImage (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_FW_IMAGE  Fw;

  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  UT_ASSERT_EQUAL (AsciiStrCmp (Fw.BuildTime, "20260101120000"), 0);
  UT_ASSERT_EQUAL (AsciiStrCmp (Fw.Platform, "ALPS"), 0);
  UT_ASSERT_EQUAL (Fw.HwVer, 0x8A);
  UT_ASSERT_EQUAL (Fw.SectionCount, SYN_SECTIONS);
  UT_ASSERT_EQUAL (Fw.Sections[0].Offset, mSynOffset[0]);
  UT_ASSERT_EQUAL (Fw.Sections[1].DlAddr, 0x0091C000);
  UT_ASSERT_EQUAL (Fw.Sections[2].DlSize, SYN_SEC2_SIZE);
  UT_ASSERT_EQUAL (Fw.Sections[3].DlSize, 0);
  UT_ASSERT_EQUAL (Fw.Sections[1].Crc, 0x12340001);
  UT_ASSERT_TRUE (Fw.Sections[2].Data == mSynImage + mSynOffset[2]);
  UT_ASSERT_TRUE (Fw.Sections[3].Data == NULL);
  UT_ASSERT_EQUAL (Fw.DownloadBytes, SYN_SEC0_SIZE + SYN_SEC1_SIZE + SYN_SEC2_SIZE);
  UT_ASSERT_EQUAL (Fw.DownloadChunks, 4 + 2 + 1);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
ParseRejectsBadImages (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_FW_IMAGE  Fw;
  UINT8         *Copy;
  UINT8         *Map;

  BuildSyntheticImage ();
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (mSynImage, 50, &Fw), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (mSynImage, SYN_MAPS_END - 1, &Fw), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (mSynImage, sizeof (mSynImage) - SYN_INFO_SIZE - 1, &Fw), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (NULL, sizeof (mSynImage), &Fw), EFI_INVALID_PARAMETER);

  Copy = AllocateCopyPool (sizeof (mSynImage), mSynImage);
  UT_ASSERT_NOT_NULL (Copy);

  PutLe32 (Copy + MTK_FW_HEADER_SIZE + 12, 0);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (Copy, sizeof (mSynImage), &Fw), EFI_VOLUME_CORRUPTED);

  PutLe32 (Copy + MTK_FW_HEADER_SIZE + 12, MTK_FW_MAX_SECTIONS + 1);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (Copy, sizeof (mSynImage), &Fw), EFI_UNSUPPORTED);

  //
  // Section offset pointing past the end of the file.
  //
  PutLe32 (Copy + MTK_FW_HEADER_SIZE + 12, SYN_SECTIONS);
  Map = Copy + MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE + 1 * MTK_FW_SECTION_MAP_SIZE;
  PutLe32 (Map + 4, 0xFFFFFF00);
  UT_ASSERT_STATUS_EQUAL (MtkFwParse (Copy, sizeof (mSynImage), &Fw), EFI_VOLUME_CORRUPTED);

  FreePool (Copy);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
FirmwareNames (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  Name[48];

  UT_ASSERT_NOT_EFI_ERROR (MtkBtFirmwareName (0x7922, 0x00000000, 0, Name, sizeof (Name)));
  UT_ASSERT_EQUAL (AsciiStrCmp (Name, "BT_RAM_CODE_MT7922_1_1_hdr.bin"), 0);
  UT_ASSERT_NOT_EFI_ERROR (MtkBtFirmwareName (0x7961, 0x8A000001, 1, Name, sizeof (Name)));
  UT_ASSERT_EQUAL (AsciiStrCmp (Name, "BT_RAM_CODE_MT7961_1a_2_hdr.bin"), 0);
  UT_ASSERT_NOT_EFI_ERROR (MtkBtFirmwareName (0x7922, 0x0000000F, 1, Name, sizeof (Name)));
  UT_ASSERT_EQUAL (AsciiStrCmp (Name, "BT_RAM_CODE_MT7922_1_10_hdr.bin"), 0);
  UT_ASSERT_STATUS_EQUAL (MtkBtFirmwareName (0x7925, 0, 0, Name, sizeof (Name)), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (MtkBtFirmwareName (0x7922, 0, 0, Name, 10), EFI_BUFFER_TOO_SMALL);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
ChipInfoAndEnable (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM        Sim;
  MTK_BT_DEVICE  Dev;
  UINT32         ChipId;
  UINT32         FwVersion;
  UINT32         FwFlavor;
  MTK_WMT_EVENT  Event;

  MtkSimInit (&Sim);
  Sim.EmptyPolls = 2;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtGetChipInfo (&Dev, &ChipId, &FwVersion, &FwFlavor));
  UT_ASSERT_EQUAL (ChipId, 0x7922);
  UT_ASSERT_EQUAL (FwVersion, 0);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtEnable (&Dev, &Event));
  UT_ASSERT_EQUAL (Sim.RegEpRstOpt, MTK_BT_UHW_EP_RST_IN_OUT);
  UT_ASSERT_TRUE (Sim.FunctionOn);
  UT_ASSERT_EQUAL (Event.Op, MTK_WMT_OP_FUNC_CTRL);
  UT_ASSERT_TRUE (Event.HasStatus);
  UT_ASSERT_EQUAL (Event.Status, 0x0404);
  UT_ASSERT_EQUAL (Sim.Polls, 3);                   // two empty polls, then the event
  UT_ASSERT_EQUAL (Dev.ShortPolls, 3);              // all of them short, EDK2-style
  UT_ASSERT_EQUAL (Sim.ElapsedUs, 2 * 500);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtDisable (&Dev, &Event));
  UT_ASSERT_FALSE (Sim.FunctionOn);
  UT_ASSERT_FALSE (Event.HasStatus);
  UT_ASSERT_EQUAL (Sim.FuncCtrls, 2);
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
AlreadyLoadedSendsNoData (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_IMAGE        Fw;
  MTK_FW_LOAD_RESULT  Result;

  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  SimWithSyntheticSections (&Sim, TRUE);
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtLoadFirmware (&Dev, &Fw, FALSE, &Result));
  UT_ASSERT_EQUAL (Result.SectionsChecked, 3);
  UT_ASSERT_EQUAL (Result.SectionsAlreadyLoaded, 3);
  UT_ASSERT_EQUAL (Result.ChunksSent, 0);
  UT_ASSERT_EQUAL (Result.FirstMissingSection, -1);
  UT_ASSERT_EQUAL (Sim.Queries, 3);
  UT_ASSERT_EQUAL (Sim.Chunks, 0);
  UT_ASSERT_EQUAL (Sim.ElapsedUs, 100 * 1000);      // activation wait only
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
WorksWhenShortRepliesAreNotFlagged (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_IMAGE        Fw;
  MTK_FW_LOAD_RESULT  Result;

  //
  // A USB stack that returns success for short transfers without saying so:
  // the zero-filled buffer alone has to tell "no event yet" from an event.
  //
  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  SimWithSyntheticSections (&Sim, FALSE);
  Sim.ReportShort = FALSE;
  Sim.EmptyPolls  = 2;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtLoadFirmware (&Dev, &Fw, TRUE, &Result));
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  UT_ASSERT_EQUAL (Result.ChunksSent, Fw.DownloadChunks);
  UT_ASSERT_EQUAL (Dev.ShortPolls, 0);
  UT_ASSERT_EQUAL (Dev.EventPolls, 3 * Dev.WmtCommands);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
ShortRegisterReadIsAnError (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM        Sim;
  MTK_BT_DEVICE  Dev;
  UINT32         Value;

  MtkSimInit (&Sim);
  Sim.ShortRegisterReads = TRUE;
  MtkBtInitDevice (&Dev, &Sim.Transport);
  UT_ASSERT_STATUS_EQUAL (MtkBtReadChipReg (&Dev, MTK_BT_REG_CHIP_ID, &Value), EFI_PROTOCOL_ERROR);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
MissingSectionNotUploadedByDefault (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_IMAGE        Fw;
  MTK_FW_LOAD_RESULT  Result;

  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  SimWithSyntheticSections (&Sim, TRUE);
  Sim.Loaded[1] = FALSE;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_STATUS_EQUAL (MtkBtLoadFirmware (&Dev, &Fw, FALSE, &Result), EFI_NOT_STARTED);
  UT_ASSERT_EQUAL (Result.FirstMissingSection, 1);
  UT_ASSERT_EQUAL (Result.ChunksSent, 0);
  UT_ASSERT_EQUAL (Sim.Chunks, 0);
  UT_ASSERT_EQUAL (Sim.Queries, 2);
  UT_ASSERT_FALSE (Sim.Loaded[1]);
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
UploadWithBusyAndSlowEvents (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_IMAGE        Fw;
  MTK_FW_LOAD_RESULT  Result;

  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  SimWithSyntheticSections (&Sim, FALSE);
  Sim.BusyReplies = 2;
  Sim.EmptyPolls  = 3;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtLoadFirmware (&Dev, &Fw, TRUE, &Result));
  UT_LOG_INFO ("simulator: %a\n", (Sim.Error[0] != 0) ? Sim.Error : "no violations");
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  UT_ASSERT_TRUE (Sim.Loaded[0] && Sim.Loaded[1] && Sim.Loaded[2]);
  UT_ASSERT_EQUAL (Result.SectionsDownloaded, 3);
  UT_ASSERT_EQUAL (Result.BusyRetries, 2);
  UT_ASSERT_EQUAL (Result.ChunksSent, Fw.DownloadChunks);
  UT_ASSERT_EQUAL (Sim.Chunks, Fw.DownloadChunks);
  UT_ASSERT_EQUAL (Sim.Queries, 3 + 2);
  UT_ASSERT_EQUAL (Dev.WmtCommands, 3 + 2 + Fw.DownloadChunks);
  UT_ASSERT_EQUAL (Sim.Polls, 4 * Dev.WmtCommands);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
BusyForeverTimesOut (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_IMAGE        Fw;
  MTK_FW_LOAD_RESULT  Result;

  BuildSyntheticImage ();
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (mSynImage, sizeof (mSynImage), &Fw));
  SimWithSyntheticSections (&Sim, FALSE);
  Sim.BusyReplies = 1000;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_STATUS_EQUAL (MtkBtLoadFirmware (&Dev, &Fw, TRUE, &Result), EFI_TIMEOUT);
  UT_ASSERT_EQUAL (Sim.Queries, 20);
  UT_ASSERT_EQUAL (Sim.Chunks, 0);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
SilentChipTimesOut (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM        Sim;
  MTK_BT_DEVICE  Dev;

  MtkSimInit (&Sim);
  Sim.NeverReply = TRUE;
  MtkBtInitDevice (&Dev, &Sim.Transport);
  Dev.EventTimeoutMs = 20;

  UT_ASSERT_STATUS_EQUAL (MtkBtEnable (&Dev, NULL), EFI_TIMEOUT);
  UT_ASSERT_EQUAL (Sim.Polls, 41);                  // 20 ms / 500 us, plus the first poll
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
SubsysResetDropsFirmware (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MTK_SIM        Sim;
  MTK_BT_DEVICE  Dev;

  BuildSyntheticImage ();
  SimWithSyntheticSections (&Sim, TRUE);
  Sim.FunctionOn     = TRUE;
  Sim.ResetDonePolls = 3;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtSubsysReset7922 (&Dev));
  UT_ASSERT_FALSE (Sim.Loaded[0]);
  UT_ASSERT_FALSE (Sim.FunctionOn);
  UT_ASSERT_EQUAL (Sim.RegSubsysRst & 0x2020, 0x2020);
  UT_ASSERT_EQUAL (Sim.RegUdmaIntSta, 0xFF);
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
RealFirmwareFullUpload (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  HOST_FILE           *File;
  UINT8               *Image;
  UINTN               Size;
  MTK_FW_IMAGE        *Fw;
  MTK_SIM             Sim;
  MTK_BT_DEVICE       Dev;
  MTK_FW_LOAD_RESULT  Result;
  UINT32              Index;

  if (mFirmwarePath == NULL) {
    UT_LOG_WARNING ("no firmware path given on the command line; skipping\n");
    return UNIT_TEST_SKIPPED;
  }

  File = fopen (mFirmwarePath, "rb");
  UT_ASSERT_NOT_NULL (File);
  Image = AllocatePool (SIZE_4MB);
  UT_ASSERT_NOT_NULL (Image);
  Size = fread (Image, 1, SIZE_4MB, File);
  fclose (File);

  Fw = AllocateZeroPool (sizeof (*Fw));
  UT_ASSERT_NOT_NULL (Fw);
  UT_ASSERT_NOT_EFI_ERROR (MtkFwParse (Image, Size, Fw));
  UT_LOG_INFO (
    "%a: %u bytes, build %a, %u sections, %u bytes / %u chunks to send\n",
    mFirmwarePath,
    (UINT32)Size,
    Fw->BuildTime,
    Fw->SectionCount,
    Fw->DownloadBytes,
    Fw->DownloadChunks
    );

  //
  // Numbers cross-checked with an independent Python parser of the same file.
  //
  UT_ASSERT_EQUAL (Size, 517398);
  UT_ASSERT_EQUAL (AsciiStrCmp (Fw->BuildTime, "20260724143815"), 0);
  UT_ASSERT_EQUAL (AsciiStrCmp (Fw->Platform, "ALPS"), 0);
  UT_ASSERT_EQUAL (Fw->SectionCount, 3);
  UT_ASSERT_EQUAL (Fw->Sections[0].Offset, 0x120);
  UT_ASSERT_EQUAL (Fw->Sections[0].DlSize, 80128);
  UT_ASSERT_EQUAL (Fw->Sections[0].DlAddr, 0x00900000);
  UT_ASSERT_EQUAL (Fw->Sections[1].Offset, 0x13A20);
  UT_ASSERT_EQUAL (Fw->Sections[1].DlSize, 436864);
  UT_ASSERT_EQUAL (Fw->Sections[1].DlAddr, 0x0091C000);
  UT_ASSERT_EQUAL (Fw->Sections[2].DlSize, 0);
  UT_ASSERT_EQUAL (Fw->DownloadBytes, 516992);
  UT_ASSERT_EQUAL (Fw->DownloadChunks, 2069);

  //
  // The simulator takes its expected bytes straight from the file offsets,
  // independently of the parser's Data pointers.
  //
  MtkSimInit (&Sim);
  MtkSimAddSection (&Sim, 0x00900000, 80128, Image + 0x120, FALSE);
  MtkSimAddSection (&Sim, 0x0091C000, 436864, Image + 0x13A20, FALSE);
  Sim.EmptyPolls = 1;
  MtkBtInitDevice (&Dev, &Sim.Transport);

  UT_ASSERT_NOT_EFI_ERROR (MtkBtLoadFirmware (&Dev, Fw, TRUE, &Result));
  UT_LOG_INFO ("simulator: %a\n", (Sim.Error[0] != 0) ? Sim.Error : "no violations");
  UT_ASSERT_EQUAL (Sim.Error[0], 0);
  for (Index = 0; Index < 2; Index++) {
    UT_ASSERT_TRUE (Sim.Loaded[Index]);
  }

  UT_ASSERT_EQUAL (Result.ChunksSent, 2069);
  UT_ASSERT_EQUAL (Dev.WmtCommands, 2 + 2069);
  UT_LOG_INFO (
    "upload: %u WMT commands, %u polls, %u ms of stalls with one empty poll per event\n",
    Dev.WmtCommands,
    Sim.Polls,
    (UINT32)(Sim.ElapsedUs / 1000)
    );

  FreePool (Fw);
  FreePool (Image);
  return UNIT_TEST_PASSED;
}

STATIC
EFI_STATUS
EFIAPI
UnitTestingEntry (
  VOID
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      ParseSuite;
  UNIT_TEST_SUITE_HANDLE      WmtSuite;

  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = CreateUnitTestSuite (&ParseSuite, Framework, "Firmware image parsing", "MtkBtLib.Parse", NULL, NULL);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  AddTestCase (ParseSuite, "Synthetic image parses with the right fields", "Synthetic", ParseSyntheticImage, NULL, NULL, NULL);
  AddTestCase (ParseSuite, "Truncated and inconsistent images are rejected", "Reject", ParseRejectsBadImages, NULL, NULL, NULL);
  AddTestCase (ParseSuite, "Firmware file names follow the Linux scheme", "Names", FirmwareNames, NULL, NULL, NULL);

  Status = CreateUnitTestSuite (&WmtSuite, Framework, "WMT channel against a simulated MT7922", "MtkBtLib.Wmt", NULL, NULL);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  AddTestCase (WmtSuite, "Chip info, enable and disable", "Enable", ChipInfoAndEnable, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "Loaded sections are only queried", "AlreadyLoaded", AlreadyLoadedSendsNoData, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "Works when the USB stack does not flag short replies", "Unflagged", WorksWhenShortRepliesAreNotFlagged, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "A short register read is an error", "ShortReg", ShortRegisterReadIsAnError, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "A missing section is not uploaded without permission", "NoUpload", MissingSectionNotUploadedByDefault, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "Upload survives busy replies and slow events", "Upload", UploadWithBusyAndSlowEvents, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "A chip that stays busy gives up after 20 queries", "Busy", BusyForeverTimesOut, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "A silent chip times out", "Silent", SilentChipTimesOut, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "MT7922 subsystem reset sequence", "Reset", SubsysResetDropsFirmware, NULL, NULL, NULL);
  AddTestCase (WmtSuite, "Real MT7922 image uploads chunk-for-chunk", "RealImage", RealFirmwareFullUpload, NULL, NULL, NULL);

  Status = RunAllTestSuites (Framework);

Exit:
  if (Framework != NULL) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  if (argc > 1) {
    mFirmwarePath = argv[1];
  }

  return (int)UnitTestingEntry ();
}
