/** @file
  MediaTek MT79xx firmware image parsing (no I/O).

  Image layout:
    0x00  header (32 bytes): build time[16], platform[4], hw ver, sw ver, magic
    0x20  global descriptor (64 bytes): patch ver, subsystem, feature options,
          section count, ...
    0x60  section maps, 64 bytes each:
            +0  section type
            +4  file offset of the payload
            +8  payload size
            +12 bin info block (52 bytes) sent verbatim with the section query:
                +0 load address, +4 download size, +8 key index, +12 align,
                +16 type, +20 download mode / CRC type, +24 CRC, rest reserved

  Copyright (c) 2026, Dávid Balatoni
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/MtkBtLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

STATIC
UINT32
ReadLe32 (
  IN CONST UINT8  *Ptr
  )
{
  return (UINT32)Ptr[0] | ((UINT32)Ptr[1] << 8) | ((UINT32)Ptr[2] << 16) | ((UINT32)Ptr[3] << 24);
}

STATIC
UINT16
ReadLe16 (
  IN CONST UINT8  *Ptr
  )
{
  return (UINT16)(Ptr[0] | (Ptr[1] << 8));
}

/**
  Copy a fixed-width field and stop at the first NUL or non-printable byte.
**/
STATIC
VOID
CopyAsciiField (
  OUT CHAR8        *Dest,
  IN  CONST UINT8  *Src,
  IN  UINTN        Width
  )
{
  UINTN  Index;

  for (Index = 0; Index < Width; Index++) {
    if ((Src[Index] < 0x20) || (Src[Index] > 0x7E)) {
      break;
    }

    Dest[Index] = (CHAR8)Src[Index];
  }

  Dest[Index] = '\0';
}

EFI_STATUS
EFIAPI
MtkFwParse (
  IN  CONST VOID    *Image,
  IN  UINTN         ImageSize,
  OUT MTK_FW_IMAGE  *Fw
  )
{
  CONST UINT8     *Bytes;
  CONST UINT8     *Map;
  MTK_FW_SECTION  *Section;
  UINT32          Count;
  UINT32          Index;
  UINT64          MapsEnd;

  if ((Image == NULL) || (Fw == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Fw, sizeof (*Fw));
  Bytes = (CONST UINT8 *)Image;

  if (ImageSize < MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE) {
    DEBUG ((DEBUG_ERROR, "MtkFwParse: image too small (%u bytes)\n", (UINT32)ImageSize));
    return EFI_VOLUME_CORRUPTED;
  }

  CopyAsciiField (Fw->BuildTime, Bytes, 16);
  CopyAsciiField (Fw->Platform, Bytes + 16, 4);
  Fw->HwVer = ReadLe16 (Bytes + 20);
  Fw->SwVer = ReadLe16 (Bytes + 22);
  Fw->Magic = ReadLe32 (Bytes + 24);

  Count = ReadLe32 (Bytes + MTK_FW_HEADER_SIZE + 12);
  if (Count == 0) {
    DEBUG ((DEBUG_ERROR, "MtkFwParse: image declares no sections\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  if (Count > MTK_FW_MAX_SECTIONS) {
    DEBUG ((DEBUG_ERROR, "MtkFwParse: %u sections, max %u\n", Count, MTK_FW_MAX_SECTIONS));
    return EFI_UNSUPPORTED;
  }

  MapsEnd = (UINT64)MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE + (UINT64)Count * MTK_FW_SECTION_MAP_SIZE;
  if (MapsEnd > ImageSize) {
    DEBUG ((DEBUG_ERROR, "MtkFwParse: section maps truncated\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  Fw->SectionCount = Count;

  for (Index = 0; Index < Count; Index++) {
    Map     = Bytes + MTK_FW_HEADER_SIZE + MTK_FW_GLOBAL_DESC_SIZE + Index * MTK_FW_SECTION_MAP_SIZE;
    Section = &Fw->Sections[Index];

    Section->SecType       = ReadLe32 (Map + 0);
    Section->Offset        = ReadLe32 (Map + 4);
    Section->Size          = ReadLe32 (Map + 8);
    Section->BinInfo       = Map + MTK_FW_SECTION_COMMON_SIZE;
    Section->DlAddr        = ReadLe32 (Section->BinInfo + 0);
    Section->DlSize        = ReadLe32 (Section->BinInfo + 4);
    Section->BinType       = ReadLe32 (Section->BinInfo + 16);
    Section->DlModeCrcType = ReadLe32 (Section->BinInfo + 20);
    Section->Crc           = ReadLe32 (Section->BinInfo + 24);

    if (Section->DlSize == 0) {
      continue;
    }

    //
    // Linux sends DlSize bytes starting at Offset; both must lie inside the file.
    //
    if (((UINT64)Section->Offset + Section->DlSize) > ImageSize) {
      DEBUG ((
        DEBUG_ERROR,
        "MtkFwParse: section %u out of bounds (offset 0x%x, size %u, file %u)\n",
        Index,
        Section->Offset,
        Section->DlSize,
        (UINT32)ImageSize
        ));
      return EFI_VOLUME_CORRUPTED;
    }

    Section->Data       = Bytes + Section->Offset;
    Fw->DownloadBytes  += Section->DlSize;
    Fw->DownloadChunks += (Section->DlSize + MTK_WMT_MAX_PAYLOAD - 1) / MTK_WMT_MAX_PAYLOAD;
  }

  return EFI_SUCCESS;
}

/**
  Append a lowercase hex number without leading zeros.
**/
STATIC
UINTN
AppendHex (
  OUT CHAR8   *Buffer,
  IN  UINTN   Pos,
  IN  UINT32  Value,
  IN  UINTN   MinDigits
  )
{
  CHAR8  Digits[8];
  UINTN  Count;

  Count = 0;
  do {
    Digits[Count++] = "0123456789abcdef"[Value & 0xF];
    Value         >>= 4;
  } while ((Value != 0) || (Count < MinDigits));

  while (Count > 0) {
    Buffer[Pos++] = Digits[--Count];
  }

  return Pos;
}

STATIC
UINTN
AppendString (
  OUT CHAR8        *Buffer,
  IN  UINTN        Pos,
  IN  CONST CHAR8  *String
  )
{
  while (*String != '\0') {
    Buffer[Pos++] = *String++;
  }

  return Pos;
}

EFI_STATUS
EFIAPI
MtkBtFirmwareName (
  IN  UINT32  ChipId,
  IN  UINT32  FwVersion,
  IN  UINT32  FwFlavor,
  OUT CHAR8   *Buffer,
  IN  UINTN   BufferSize
  )
{
  CHAR8  Name[48];
  UINTN  Pos;

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((ChipId != 0x7922) && (ChipId != 0x7961) && (ChipId != 0x7902)) {
    return EFI_UNSUPPORTED;
  }

  //
  // BT_RAM_CODE_MT<chip>_1[a]_<(version & 0xff) + 1>_hdr.bin; the "1a" flavor
  // only exists for MT7961.
  //
  Pos = AppendString (Name, 0, "BT_RAM_CODE_MT");
  Pos = AppendHex (Name, Pos, ChipId & 0xFFFF, 4);
  Pos = AppendString (Name, Pos, ((ChipId == 0x7961) && (FwFlavor != 0)) ? "_1a_" : "_1_");
  Pos = AppendHex (Name, Pos, (FwVersion & 0xFF) + 1, 1);
  Pos = AppendString (Name, Pos, "_hdr.bin");
  Name[Pos++] = '\0';

  if (Pos > BufferSize) {
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Buffer, Name, Pos);
  return EFI_SUCCESS;
}
