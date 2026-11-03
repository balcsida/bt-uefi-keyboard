## @file
#  Host-based unit tests for BtKbPkg.
#
#  Build:  build -p BtKbPkg/Test/BtKbPkgHostTest.dsc -a X64 -t GCC -b NOOPT
#  Run:    Build/BtKbPkg/HostTest/NOOPT_GCC/X64/MtkBtLibUnitTestHost [firmware.bin]
#
#  SPDX-License-Identifier: MIT OR Apache-2.0
##

[Defines]
  PLATFORM_NAME           = BtKbPkgHostTest
  PLATFORM_GUID           = DCF0E9B5-608F-46D0-97AD-C42E87A943AC
  PLATFORM_VERSION        = 0.1
  DSC_SPECIFICATION       = 0x00010017
  OUTPUT_DIRECTORY        = Build/BtKbPkg/HostTest
  SUPPORTED_ARCHITECTURES = X64
  BUILD_TARGETS           = NOOPT
  SKUID_IDENTIFIER        = DEFAULT

!include UnitTestFrameworkPkg/UnitTestFrameworkPkgHost.dsc.inc

[Components]
  BtKbPkg/Library/MtkBtLib/UnitTest/MtkBtLibUnitTestHost.inf {
    <LibraryClasses>
      MtkBtLib|BtKbPkg/Library/MtkBtLib/MtkBtLib.inf
  }
