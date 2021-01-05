#  EFI/Framework TDVF platform
#  Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
[Defines]
  PLATFORM_NAME                  = TdShim
  PLATFORM_GUID                  = 173A0F06-F54A-44D5-BF91-B631F80BA036
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/TdShim
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = NOOPT|DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = TdShimPkg/TdShimPkg.fdf

  #
  # Defines for default states.  These can be changed on the command line.
  # -D FLAG=VALUE
  #
  DEFINE TDX_EMULATION_ENABLE    = FALSE
  DEFINE SOFT_RTMR               = FALSE
  DEFINE TDX_IGNORE_VE_HLT       = FALSE
  DEFINE TDX_DISABLE_SHARED_MASK = FALSE

#DEFINE CRYPT_LIB = OPENSSL
#DEFINE CRYPT_LIB = MBEDTLS
DEFINE CRYPT_LIB = MBEDTLS

  #
  # Flash size selection. Setting FD_SIZE_IN_KB on the command line directly to
  # one of the supported values, in place of any of the convenience macros, is
  # permitted.
  #
!ifdef $(FD_SIZE_1MB)
  DEFINE FD_SIZE_IN_KB           = 1024
!else
!ifdef $(FD_SIZE_2MB)
  DEFINE FD_SIZE_IN_KB           = 2048
!else
!ifdef $(FD_SIZE_4MB)
  DEFINE FD_SIZE_IN_KB           = 4096
!else
  DEFINE FD_SIZE_IN_KB           = 4096
!endif
!endif
!endif

[BuildOptions]
  GCC:RELEASE_*_*_CC_FLAGS             = -DMDEPKG_NDEBUG
  INTEL:RELEASE_*_*_CC_FLAGS           = /D MDEPKG_NDEBUG
  MSFT:RELEASE_*_*_CC_FLAGS            = /D MDEPKG_NDEBUG
!if $(TOOL_CHAIN_TAG) != "XCODE5"
  GCC:*_*_*_CC_FLAGS                   = -mno-mmx -mno-sse
!endif
!ifdef $(SOURCE_DEBUG_ENABLE)
  MSFT:*_*_X64_GENFW_FLAGS  = --keepexceptiontable
  GCC:*_*_X64_GENFW_FLAGS   = --keepexceptiontable
  INTEL:*_*_X64_GENFW_FLAGS = --keepexceptiontable
!endif

  #
  # Define SOFT_RTMR
  #
!if $(SOFT_RTMR) == TRUE
  MSFT:*_*_*_CC_FLAGS = /D SOFT_RTMR
  INTEL:*_*_*_CC_FLAGS = /D SOFT_RTMR
  GCC:*_*_*_CC_FLAGS = -D SOFT_RTMR
!endif

  #
  # Disable deprecated APIs.
  #
  MSFT:*_*_*_CC_FLAGS = /D DISABLE_NEW_DEPRECATED_INTERFACES
  INTEL:*_*_*_CC_FLAGS = /D DISABLE_NEW_DEPRECATED_INTERFACES
  GCC:*_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES

[BuildOptions.common.EDKII.DXE_RUNTIME_DRIVER]
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000
  XCODE:*_*_*_DLINK_FLAGS =

# Force PE/COFF sections to be aligned at 4KB boundaries to support page level
# protection of DXE_SMM_DRIVER/SMM_CORE modules
[BuildOptions.common.EDKII.DXE_SMM_DRIVER, BuildOptions.common.EDKII.SMM_CORE]
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000
  XCODE:*_*_*_DLINK_FLAGS =

#s###############################################################################
#
# SKU Identification section - list of all SKU IDs supported by this Platform.
#
################################################################################
[SkuIds]
  0|DEFAULT

################################################################################
#
# Library Class section - list of all Library Classes needed by this Platform.
#
################################################################################
[LibraryClasses]
  TimerLib|UefiCpuPkg/Library/SecPeiDxeTimerLibUefiCpu/SecPeiDxeTimerLibUefiCpu.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  CacheMaintenanceLib|MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
  UefiDecompressLib|MdePkg/Library/BaseUefiDecompressLib/BaseUefiDecompressLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  IoLib|TdShimPkg/Library/BaseIoLibIntrinsicTdx/BaseIoLibIntrinsicTdx.inf
  OemHookStatusCodeLib|MdeModulePkg/Library/OemHookStatusCodeLibNull/OemHookStatusCodeLibNull.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  UefiCpuLib|UefiCpuPkg/Library/BaseUefiCpuLib/BaseUefiCpuLib.inf
  HashApiLib|CryptoPkg/Library/BaseHashApiLib/BaseHashApiLib.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf

  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  DebugAgentLib|MdeModulePkg/Library/DebugAgentLibNull/DebugAgentLibNull.inf

  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibCrypto.inf
  #MbedTlsLib|CryptoMbedTlsPkg/Library/MbedTlsLib/MbedTlsLib.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf

  SmbusLib|MdePkg/Library/BaseSmbusLibNull/BaseSmbusLibNull.inf
  OrderedCollectionLib|MdePkg/Library/BaseOrderedCollectionRedBlackTreeLib/BaseOrderedCollectionRedBlackTreeLib.inf
  TdxLib|TdShimPkg/Library/TdxLib/TdxLib.inf

  LocalApicLib|TdShimPkg/Library/BaseXApicX2ApicLib/BaseXApicX2ApicLibDxe.inf
  IoApicLib|PcAtChipsetPkg/Library/BaseIoApicLib/BaseIoApicLib.inf
  VmgExitLib|UefiCpuPkg/Library/VmgExitLibNull/VmgExitLibNull.inf
  VmTdExitLib|TdShimPkg/Library/VmTdExitLib/VmTdExitLib.inf

  VirtualMemoryLib|TdShimPkg/Library/VirtualMemoryLib/VirtualMemoryLib.inf
  MemoryEncryptionLib|TdShimPkg/Library/BaseMemEncryptTdxLib/BaseMemEncryptTdxLib.inf

!if $(CRYPT_LIB) == MBEDTLS
  #BaseCryptLib|CryptoMbedTlsPkg/Library/BaseCryptLib/CommonCryptLib.inf
!else
  #BaseCryptLib|CryptoPkg/Library/BaseCryptLib/CommonCryptLib.inf
!endif

  TdxLib|TdShimPkg/Library/TdxLib/TdxLibSec.inf
  ReportStatusCodeLib|MdeModulePkg/Library/PeiReportStatusCodeLib/PeiReportStatusCodeLib.inf
  CpuExceptionHandlerLib|TdShimPkg/Override/UefiCpuPkg/Library/CpuExceptionHandlerLib/SecPeiCpuExceptionHandlerLib.inf
  IoLib|TdShimPkg/Library/BaseIoLibIntrinsicTdx/BaseIoLibIntrinsicTdx.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  LocalApicLib|TdShimPkg/Library/BaseXApicX2ApicLib/BaseXApicX2ApicLibSec.inf

!if $(TARGET) == RELEASE
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!endif

  DxeCoreEntryPoint|MdePkg/Library/DxeCoreEntryPoint/DxeCoreEntryPoint.inf

################################################################################
#
# Pcd Section - list of all EDK II PCD Entries defined by this Platform.
#
################################################################################
[PcdsFeatureFlag]
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeIplSupportUefiDecompress|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeIplSwitchToLongMode|FALSE

[PcdsFixedAtBuild]

  # DEBUG_INIT      0x00000001  // Initialization
  # DEBUG_WARN      0x00000002  // Warnings
  # DEBUG_LOAD      0x00000004  // Load events
  # DEBUG_FS        0x00000008  // EFI File system
  # DEBUG_POOL      0x00000010  // Alloc & Free (pool)
  # DEBUG_PAGE      0x00000020  // Alloc & Free (page)
  # DEBUG_INFO      0x00000040  // Informational debug messages
  # DEBUG_DISPATCH  0x00000080  // PEI/DXE/SMM Dispatchers
  # DEBUG_VARIABLE  0x00000100  // Variable
  # DEBUG_BM        0x00000400  // Boot Manager
  # DEBUG_BLKIO     0x00001000  // BlkIo Driver
  # DEBUG_NET       0x00004000  // SNP Driver
  # DEBUG_UNDI      0x00010000  // UNDI Driver
  # DEBUG_LOADFILE  0x00020000  // LoadFile
  # DEBUG_EVENT     0x00080000  // Event messages
  # DEBUG_GCD       0x00100000  // Global Coherency Database changes
  # DEBUG_CACHE     0x00200000  // Memory range cachability changes
  # DEBUG_VERBOSE   0x00400000  // Detailed debug messages that may
  #                             // significantly impact boot performance
  # DEBUG_ERROR     0x80000000  // Error
!if $(TARGET) == RELEASE
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x00000000
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x00
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x00
!else
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80400042
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x07
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17
!endif

!if $(TDX_EMULATION_ENABLE) == TRUE
  gUefiTdShimPkgTokenSpaceGuid.PcdUseTdxEmulation|1
!endif
  gEfiMdeModulePkgTokenSpaceGuid.PcdUse1GPageTable|TRUE

  # Noexec settings for DXE.
  # TDX doesn't allow us to change EFER so make sure these are disabled
  gEfiMdeModulePkgTokenSpaceGuid.PcdImageProtectionPolicy|0x00000000
  gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy|0x00000000
  # Noexec settings for DXE.
  # TDX doesn't allow us to change EFER so make sure these are disabled
  gEfiMdeModulePkgTokenSpaceGuid.PcdSetNxForStack|FALSE

  # Set memory encryption mask
  gEfiMdeModulePkgTokenSpaceGuid.PcdPteMemoryEncryptionAddressOrMask|0x0

!if $(TDX_IGNORE_VE_HLT) == TRUE
  gUefiTdShimPkgTokenSpaceGuid.PcdIgnoreVeHalt|TRUE
!endif
!if $(TDX_DISABLE_SHARED_MASK) == TRUE
  gUefiTdShimPkgTokenSpaceGuid.PcdTdxDisableSharedMask|TRUE
!endif

################################################################################
#
# Pcd Dynamic Section - list of all EDK II PCD Entries defined by this Platform
#
################################################################################

################################################################################
#
# Components Section - list of all EDK II Modules needed by this Platform.
#
################################################################################
[Components]
  TdShimPkg/ResetVector/ResetVector.inf

  #
  # SEC Phase modules
  #
  TdShimPkg/TdShimIpl/TdShimIpl.inf {
    <LibraryClasses>
      PrePiLib|TdShimPkg/Library/PrePiLibTdx/PrePiLibTdx.inf
      HobLib|TdShimPkg/Library/PrePiHobLibTdx/PrePiHobLibTdx.inf
      PrePiHobListPointerLib|TdShimPkg/Library/PrePiHobListPointerLibTdx/PrePiHobListPointerLibTdx.inf
      MemoryAllocationLib|TdShimPkg/Library/PrePiMemoryAllocationLibTdx/PrePiMemoryAllocationLibTdx.inf
  }

  TdShimPkg/Payload/Payload.inf
